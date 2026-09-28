#!/usr/bin/env python3
"""
FileCrypt Reverse Engineering Tool - file-rev.py
Ferramenta automatizada de processamento do fluxo de verificação do FileCrypt.

PRINCÍPIO: observação → captura → correlação → evidência → conclusão
NÃO: suposição → processamento → conclusão
"""

import asyncio
import json
import uuid
import time
import hashlib
import base64
import re
import os
import sys
import argparse
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Tuple, Callable
from enum import Enum, auto
from playwright.async_api import async_playwright, Page, Browser, BrowserContext, Request, Response, Route


class ChallengeState(Enum):
    """Estados da máquina de estados do desafio"""
    INIT = "INIT"
    CHALLENGE_DISCOVERY = "CHALLENGE_DISCOVERY"
    CHALLENGE_ACQUIRED = "CHALLENGE_ACQUIRED"
    PROCESSING = "PROCESSING"
    RESULT_READY = "RESULT_READY"
    SUBMISSION = "SUBMISSION"
    SERVER_VALIDATION = "SERVER_VALIDATION"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class Challenge:
    """Modelo interno do desafio"""
    challenge_id: Optional[str] = None
    session_id: Optional[str] = None
    payload: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    client_state: Dict[str, Any] = field(default_factory=dict)
    processing_state: Dict[str, Any] = field(default_factory=dict)
    processing_result: Optional[str] = None
    submission_state: Dict[str, Any] = field(default_factory=dict)
    validation_state: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SessionContext:
    """Contexto isolado da sessão"""
    session_id: Optional[str] = None
    cookies: List[Dict] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    identifiers: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    dom_state: Dict[str, Any] = field(default_factory=dict)
    responses: List[Dict] = field(default_factory=list)
    challenge_info: Optional[Challenge] = None
    modifications: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        result = asdict(self)
        if self.challenge_info:
            result['challenge_info'] = self.challenge_info.to_dict()
        return result


@dataclass
class ScriptInfo:
    """Informações sobre scripts descobertos"""
    url: str
    name: str
    size: int = 0
    sha256: Optional[str] = None
    timestamp: Optional[str] = None
    content: Optional[str] = None
    script_type: str = "UNKNOWN"
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class WorkerMessage:
    """Mensagem de/para Worker"""
    timestamp: str
    direction: str
    worker_url: Optional[str] = None
    message_type: Optional[str] = None
    size: int = 0
    content: Any = None
    correlation_id: Optional[str] = None
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NetworkRequest:
    """Request de rede capturado"""
    request_id: str
    timestamp: str
    method: str
    url: str
    resource_type: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    classification: str = "UNCLASSIFIED"
    classification_confidence: str = "heuristic"  # heuristic, confirmed, unknown
    classification_evidence: List[str] = field(default_factory=list)
    related_challenge: Optional[str] = None
    related_session: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NetworkResponse:
    """Response de rede correlacionado ao request"""
    request_id: str
    timestamp: str
    status: int
    url: str
    content_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    size: int = 0
    body: Optional[str] = None
    parsed_body: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class EventTraceEntry:
    """Entrada do trace cronológico"""
    timestamp: str
    event_type: str
    source: str
    challenge_id: Optional[str] = None
    session_id: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class StateTransition:
    """Transição de estado baseada em evidência"""
    from_state: ChallengeState
    to_state: ChallengeState
    timestamp: str
    reason: Optional[str] = None
    evidence: Optional[str] = None
    related_request: Optional[str] = None
    related_response: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            'from_state': self.from_state.value,
            'to_state': self.to_state.value,
            'timestamp': self.timestamp,
            'reason': self.reason,
            'evidence': self.evidence,
            'related_request': self.related_request,
            'related_response': self.related_response
        }


class PoWSolver:
    """
    Solver de Proof of Work baseado em EVIDÊNCIA.
    NÃO assume algoritmo, formato ou dificuldade.
    """
    
    def __init__(self):
        self.attempts: List[Dict] = []
        self.solution: Optional[Dict] = None
        self.observed_algorithm: Optional[str] = None
        self.observed_input_format: Optional[str] = None
        self.observed_difficulty: Optional[int] = None
        
    def set_observed_params(self, algorithm: Optional[str], input_format: Optional[str], 
                           difficulty: Optional[int], evidence: str):
        """Define parâmetros APENAS quando observados no fluxo"""
        self.observed_algorithm = algorithm
        self.observed_input_format = input_format
        self.observed_difficulty = difficulty
        
    def solve(self, challenge_data: str, difficulty: Optional[int] = None) -> Optional[Dict]:
        """
        Resolve APENAS se houver evidência do algoritmo.
        Se não houver, retorna None e registra como UNKNOWN.
        """
        # CORREÇÃO: Não assume SHA-256 sem evidência
        if not self.observed_algorithm:
            return None
            
        # Se tem evidência de SHA-256, usa
        if self.observed_algorithm == "SHA-256":
            return self._solve_sha256_if_evidence(challenge_data, difficulty)
        
        # Outros algoritmos quando evidenciados
        return None
        
    def _solve_sha256_if_evidence(self, challenge_data: str, difficulty: Optional[int]) -> Optional[Dict]:
        """
        Resolve SHA-256 APENAS quando evidenciado.
        Não assume formato "challenge_data + nonce".
        """
        if not self.observed_input_format:
            return None
            
        start_time = time.time()
        nonce = 0
        
        # Usa dificuldade observada ou não resolve
        target_difficulty = difficulty or self.observed_difficulty
        if not target_difficulty:
            return None
            
        target = "0" * target_difficulty
        
        while True:
            # Usa formato observado, não assume
            if self.observed_input_format == "concat":
                payload = f"{challenge_data}{nonce}"
            elif self.observed_input_format == "json":
                payload = json.dumps({"challenge": challenge_data, "nonce": nonce})
            else:
                # Formato não determinado
                return None
                
            hash_result = hashlib.sha256(payload.encode()).hexdigest()
            
            if hash_result.startswith(target):
                elapsed = time.time() - start_time
                self.solution = {
                    "nonce": nonce,
                    "hash": hash_result,
                    "payload": payload,
                    "difficulty": target_difficulty,
                    "algorithm": "SHA-256",
                    "evidence_based": True,
                    "elapsed_time": elapsed
                }
                return self.solution
                
            nonce += 1
            
            # Timeout de segurança
            if time.time() - start_time > 300:
                return None


class FileCryptProcessor:
    """
    Processador do FileCrypt CAPTCHA baseado em EVIDÊNCIA.
    """
    
    def __init__(self):
        # Estruturas existentes - mantidas
        self.scripts: Dict[str, ScriptInfo] = {}
        self.network_requests: Dict[str, NetworkRequest] = {}
        self.network_responses: Dict[str, NetworkResponse] = {}
        self.worker_messages: List[WorkerMessage] = []
        self.worker_message_pairs: List[Tuple[str, str]] = []
        self.event_trace: List[EventTraceEntry] = []
        self.state_transitions: List[StateTransition] = []
        
        self.current_challenge: Optional[Challenge] = None
        self.current_session: Optional[SessionContext] = None
        
        self.current_state: ChallengeState = ChallengeState.INIT
        self.pow_fields_history: List[Dict] = []
        self.validation_candidates: List[Dict] = []
        self.errors: List[Dict] = []
        self.unknowns: List[Dict] = []  # CORREÇÃO: agora é lista de dicts
        
        # Dados de processamento - separados
        self.server_input: Dict[str, Any] = {}
        self.client_state: Dict[str, Any] = {}
        self.processing_data: Dict[str, Any] = {}
        self.worker_input_observed: Optional[Dict] = None
        self.worker_output_observed: Optional[Dict] = None
        self.processing_result: Optional[str] = None
        
        # Elementos DOM
        self.captcha_element_data: Dict[str, Any] = {}
        self.dom_mutations: List[Dict] = []
        
        # Solver
        self.pow_solver = PoWSolver()
        
        # CORREÇÃO: Mapeamento request/response confiável
        self._request_counter = 0
        self._request_id_map: Dict[int, str] = {}  # id(request object) -> request_id
        self._unmatched_responses: List[Dict] = []
        
        self.final_result: Optional[Dict] = None
        
    def _trace(self, event_type: str, data: Dict[str, Any], source: str = "processor"):
        """Registra evento no trace cronológico"""
        entry = EventTraceEntry(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            source=source,
            challenge_id=self.current_challenge.challenge_id if self.current_challenge else None,
            session_id=self.current_session.session_id if self.current_session else None,
            data=data
        )
        self.event_trace.append(entry)
        print(f"[TRACE:{event_type}] {str(data)[:120]}")
        
    def _transition_state(self, new_state: ChallengeState, reason: Optional[str] = None,
                         evidence: Optional[str] = None, request_id: Optional[str] = None,
                         response_id: Optional[str] = None):
        """Transiciona apenas com evidência"""
        old_state = self.current_state
        self.current_state = new_state
        
        transition = StateTransition(
            from_state=old_state,
            to_state=new_state,
            timestamp=datetime.now().isoformat(),
            reason=reason,
            evidence=evidence,
            related_request=request_id,
            related_response=response_id
        )
        self.state_transitions.append(transition)
        
        self._trace("state_transition", {
            "from": old_state.value,
            "to": new_state.value,
            "reason": reason,
            "evidence": evidence
        })
        
    def _log_error(self, context: str, error: Exception, evidence: Optional[str] = None):
        """Registra erro"""
        error_entry = {
            "timestamp": datetime.now().isoformat(),
            "context": context,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "evidence": evidence,
            "current_state": self.current_state.value
        }
        self.errors.append(error_entry)
        self._trace("error", error_entry)
        
    def _log_unknown(self, description: str, evidence: Optional[str] = None):
        """CORREÇÃO: Registra elemento não determinado com contexto"""
        unknown_entry = {
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "evidence": evidence,
            "current_state": self.current_state.value
        }
        self.unknowns.append(unknown_entry)
        self._trace("unknown", unknown_entry)
        
    def _classify_request(self, request: Request) -> Tuple[str, str, List[str]]:
        """
        CORREÇÃO #4: Classificação inicial como heurística apenas.
        Retorna: (classification, confidence, evidences)
        """
        url = request.url.lower()
        resource_type = request.resource_type
        evidences = []
        
        classification = "UNCLASSIFIED"
        confidence = "heuristic"  # Não é prova, apenas palpite inicial
        
        # Heurísticas iniciais baseadas em URL
        if 'worker' in url:
            classification = "WORKER_CANDIDATE"
            evidences.append(f"url_contains_worker: {url[:60]}")
        elif any(x in url for x in ['captcha', 'challenge', 'pow']):
            classification = "CHALLENGE_CANDIDATE"
            evidences.append(f"url_contains_challenge_term: {url[:60]}")
        elif any(x in url for x in ['session', 'sess']):
            classification = "SESSION_CANDIDATE"
            evidences.append(f"url_contains_session: {url[:60]}")
        elif any(x in url for x in ['validate', 'verify', 'check', 'submit']):
            classification = "VALIDATION_CANDIDATE"
            evidences.append(f"url_contains_validation_term: {url[:60]}")
        elif resource_type in ['script', 'javascript']:
            classification = "SCRIPT_CANDIDATE"
            evidences.append(f"resource_type_script: {resource_type}")
        else:
            confidence = "unknown"
            
        return classification, confidence, evidences
        
    async def _update_classification_with_evidence(self, req_id: str):
        """
        CORREÇÃO #4: Atualiza classificação quando há evidência adicional.
        """
        req = self.network_requests.get(req_id)
        resp = self.network_responses.get(req_id)
        
        if not req:
            return
            
        new_evidences = req.classification_evidence.copy()
        new_confidence = req.classification_confidence
        
        # Evidência do método
        if req.method in ['POST', 'PUT', 'PATCH']:
            new_evidences.append(f"http_method_{req.method}_mutation")
            
        # Evidência dos headers
        if req.headers.get('x-requested-with') == 'XMLHttpRequest':
            new_evidences.append("xhr_header")
            
        # Evidência do body
        if req.body:
            try:
                body_json = json.loads(req.body)
                new_evidences.append(f"body_json_with_keys: {list(body_json.keys())}")
                
                # Se contém campos de desafio
                if any(k.startswith('pow_') for k in body_json.keys()):
                    new_evidences.append("body_contains_pow_fields")
                    new_confidence = "confirmed"
            except:
                if any(term in req.body.lower() for term in ['pow_', 'challenge']):
                    new_evidences.append("body_contains_challenge_terms")
                    
        # Evidência da resposta
        if resp:
            if resp.status >= 200 and resp.status < 300:
                new_evidences.append(f"success_http_status_{resp.status}")
            if resp.parsed_body:
                new_evidences.append("response_parseable_json")
                
        req.classification_evidence = new_evidences
        if new_confidence != req.classification_confidence:
            req.classification_confidence = new_confidence
            
    async def _pre_instrument_workers(self, context: BrowserContext):
        """
        CORREÇÃO #7: Instrumentação antes da navegação com rastreamento cronológico.
        """
        await context.add_init_script("""
            (function() {
                const OriginalWorker = window.Worker;
                window._workerMessages = [];
                window._workerRegistry = new Map();
                
                window.Worker = function(url) {
                    const workerId = 'worker_' + Math.random().toString(36).substr(2, 9);
                    const workerUrl = url.toString();
                    const creationTime = new Date().toISOString();
                    
                    // Registra criação
                    window._workerRegistry.set(workerId, {
                        url: workerUrl,
                        createdAt: creationTime,
                        status: 'created'
                    });
                    
                    window._workerMessages.push({
                        id: 'event_create_' + Math.random().toString(36).substr(2, 9),
                        type: 'worker_created',
                        workerId: workerId,
                        workerUrl: workerUrl,
                        timestamp: creationTime,
                        data: { url: workerUrl }
                    });
                    
                    const worker = new OriginalWorker(url);
                    worker._fileRevId = workerId;
                    worker._fileRevUrl = workerUrl;
                    
                    // Intercepta postMessage (Página → Worker)
                    const originalPostMessage = worker.postMessage.bind(worker);
                    worker.postMessage = function(message, transfer) {
                        const msgId = 'msg_in_' + Math.random().toString(36).substr(2, 9);
                        const msg = {
                            id: msgId,
                            type: 'page_to_worker',
                            direction: 'page_to_worker',
                            workerId: workerId,
                            workerUrl: workerUrl,
                            timestamp: new Date().toISOString(),
                            data: message,
                            correlationId: null  # Será preenchido se possível
                        };
                        
                        // Extrai correlation_id se existir
                        if (message && typeof message === 'object') {
                            msg.correlationId = message.id || message.requestId || 
                                              message.correlationId || message.nonce || null;
                        }
                        
                        window._workerMessages.push(msg);
                        return originalPostMessage(message, transfer);
                    };
                    
                    // Intercepta onmessage (Worker → Página)
                    worker.addEventListener('message', function(event) {
                        const msgId = 'msg_out_' + Math.random().toString(36).substr(2, 9);
                        const msg = {
                            id: msgId,
                            type: 'worker_to_page',
                            direction: 'worker_to_page',
                            workerId: workerId,
                            workerUrl: workerUrl,
                            timestamp: new Date().toISOString(),
                            data: event.data,
                            correlationId: null,
                            relatedInputId: null
                        };
                        
                        // Tenta correlacionar com input
                        if (event.data && typeof event.data === 'object') {
                            const corrId = event.data.id || event.data.requestId || 
                                          event.data.correlationId || event.data.nonce;
                            
                            if (corrId) {
                                msg.correlationId = corrId;
                                
                                // Procura input correspondente
                                const relatedInput = window._workerMessages.find(m => 
                                    m.type === 'page_to_worker' && 
                                    m.correlationId === corrId
                                );
                                
                                if (relatedInput) {
                                    msg.relatedInputId = relatedInput.id;
                                    relatedInput.relatedOutputId = msgId;
                                }
                            }
                        }
                        
                        window._workerMessages.push(msg);
                    });
                    
                    // Intercepta erro
                    worker.addEventListener('error', function(error) {
                        window._workerMessages.push({
                            id: 'event_error_' + Math.random().toString(36).substr(2, 9),
                            type: 'worker_error',
                            workerId: workerId,
                            workerUrl: workerUrl,
                            timestamp: new Date().toISOString(),
                            data: { message: error.message || 'Worker error' }
                        });
                    });
                    
                    return worker;
                };
                
                window.Worker.prototype = OriginalWorker.prototype;
            })();
        """)
        
        self._trace("worker_pre_instrumentation", {"status": "active"})
        
    async def _discover_challenge(self, page: Page):
        """
        CORREÇÃO #2: Não trata data-session como ambos os IDs.
        Identifica challenge_id e session_id apenas com evidência.
        """
        self._transition_state(ChallengeState.CHALLENGE_DISCOVERY, 
                              reason="Iniciando descoberta do desafio")
        
        try:
            await page.wait_for_load_state('networkidle')
            
            captcha_exists = await page.evaluate('''() => {
                return document.getElementById('pow-captcha') !== null;
            }''')
            
            if not captcha_exists:
                self._log_unknown("Elemento #pow-captcha não encontrado")
                return False
                
            # Extrai TODOS os atributos
            captcha_data = await page.evaluate('''() => {
                const el = document.getElementById('pow-captcha');
                if (!el) return null;
                
                const data = {};
                for (const attr of el.attributes) {
                    data[attr.name] = attr.value;
                }
                return data;
            }''')
            
            self.captcha_element_data = captcha_data or {}
            
            # CORREÇÃO: Não assume data-session é ambos os IDs
            challenge_id = None
            session_id = None
            challenge_id_source = None
            session_id_source = None
            
            if captcha_data:
                # data-session → evidência sugere session_id (pelo nome)
                if 'data-session' in captcha_data:
                    session_id = captcha_data['data-session']
                    session_id_source = "data-session attribute"
                    
                # Procura por data-challenge ou similar para challenge_id
                if 'data-challenge' in captcha_data:
                    challenge_id = captcha_data['data-challenge']
                    challenge_id_source = "data-challenge attribute"
                elif 'data-id' in captcha_data:
                    challenge_id = captcha_data['data-id']
                    challenge_id_source = "data-id attribute"
                # Se não encontrar específico, challenge_id permanece None
                
            # Se não encontrou session_id, procura em cookies
            if not session_id:
                cookies = await page.context.cookies()
                for cookie in cookies:
                    if 'session' in cookie.get('name', '').lower():
                        session_id = cookie['value']
                        session_id_source = f"cookie:{cookie['name']}"
                        break
                        
            self.current_challenge = Challenge(
                challenge_id=challenge_id,  # None se não houver evidência
                session_id=session_id,      # None se não houver evidência
                payload=json.dumps(captcha_data) if captcha_data else None,
                parameters={
                    'captcha_attributes': captcha_data,
                    'challenge_id_source': challenge_id_source,
                    'session_id_source': session_id_source,
                    'discovery_timestamp': datetime.now().isoformat()
                },
                source="DOM#pow-captcha",
                created_at=datetime.now().isoformat()
            )
            
            self.server_input = {
                'captcha_element_attributes': captcha_data,
                'challenge_id': challenge_id,
                'challenge_id_source': challenge_id_source,
                'session_id': session_id,
                'session_id_source': session_id_source,
                'timestamp': datetime.now().isoformat()
            }
            
            self.client_state = {
                'timestamp': datetime.now().isoformat()
            }
            
            # Registra unknowns se IDs não foram encontrados
            if not challenge_id:
                self._log_unknown("challenge_id não identificado", 
                                "Nenhum atributo data-challenge ou similar encontrado")
            if not session_id:
                self._log_unknown("session_id não identificado",
                                "Nenhum data-session ou cookie de sessão encontrado")
            
            self._transition_state(ChallengeState.CHALLENGE_ACQUIRED,
                                  reason="Elemento #pow-captcha encontrado",
                                  evidence=json.dumps({
                                      'challenge_id': challenge_id,
                                      'challenge_id_source': challenge_id_source,
                                      'session_id': session_id,
                                      'session_id_source': session_id_source
                                  }))
            
            return True
            
        except Exception as e:
            self._log_error("discover_challenge", e)
            self._transition_state(ChallengeState.ERROR, reason=str(e))
            return False
            
    async def _capture_scripts(self, page: Page):
        """
        CORREÇÃO #6: Realmente preenche self.scripts com dados dos scripts.
        """
        try:
            scripts_data = await page.evaluate('''() => {
                const scripts = [];
                document.querySelectorAll('script').forEach((script, index) => {
                    scripts.push({
                        index: index,
                        src: script.src || null,
                        content: script.src ? null : script.textContent,
                        type: script.type || 'text/javascript',
                        async: script.async,
                        defer: script.defer
                    });
                });
                return scripts;
            }''')
            
            for script_info in scripts_data:
                url = script_info.get('src')
                
                if url:
                    # Determina tipo com evidência
                    url_lower = url.lower()
                    script_type = "SCRIPT_OTHER"
                    
                    # Heurística inicial
                    if 'pow' in url_lower or 'captcha' in url_lower:
                        script_type = "SCRIPT_CAPTCHA_CANDIDATE"
                    elif 'worker' in url_lower:
                        script_type = "SCRIPT_WORKER_CANDIDATE"
                        
                    # Tenta obter conteúdo e calcular SHA-256
                    content = None
                    size = 0
                    sha256 = None
                    
                    try:
                        # Tenta fetch para mesma origem
                        response = await page.evaluate(f'''async () => {{
                            try {{
                                const res = await fetch("{url}");
                                if (res.ok) {{
                                    const text = await res.text();
                                    return text;
                                }}
                                return null;
                            }} catch(e) {{
                                return null;
                            }}
                        }}''')
                        
                        if response:
                            content = response
                            size = len(response)
                            sha256 = hashlib.sha256(response.encode()).hexdigest()
                    except Exception as e:
                        pass
                        
                    # Cria ScriptInfo e adiciona ao dicionário
                    script_name = url.split('/')[-1].split('?')[0] if '/' in url else url
                    
                    self.scripts[url] = ScriptInfo(
                        url=url,
                        name=script_name,
                        size=size,
                        sha256=sha256,
                        timestamp=datetime.now().isoformat(),
                        content=content[:2000] if content else None,  # Amostra
                        script_type=script_type
                    )
                    
                    self._trace("script_captured", {
                        "url": url,
                        "name": script_name,
                        "type": script_type,
                        "size": size,
                        "sha256": sha256[:16] + "..." if sha256 else None
                    })
                    
        except Exception as e:
            self._log_error("capture_scripts", e)
            
    async def _collect_worker_messages(self, page: Page):
        """
        CORREÇÃO #7: Coleta mensagens com rastreamento cronológico completo.
        """
        try:
            messages = await page.evaluate('() => window._workerMessages || []')
            
            for msg in messages:
                worker_msg = WorkerMessage(
                    timestamp=msg.get('timestamp', datetime.now().isoformat()),
                    direction=msg.get('direction') or msg.get('type', 'unknown'),
                    worker_url=msg.get('workerUrl'),
                    content=msg.get('data'),
                    correlation_id=msg.get('correlationId'),
                    message_id=msg.get('id', str(uuid.uuid4()))
                )
                self.worker_messages.append(worker_msg)
                
                # Armazena observações de input/output
                if worker_msg.direction == 'page_to_worker':
                    self.worker_input_observed = {
                        'timestamp': worker_msg.timestamp,
                        'content': worker_msg.content,
                        'worker_url': worker_msg.worker_url,
                        'message_id': worker_msg.message_id
                    }
                elif worker_msg.direction == 'worker_to_page':
                    self.worker_output_observed = {
                        'timestamp': worker_msg.timestamp,
                        'content': worker_msg.content,
                        'worker_url': worker_msg.worker_url,
                        'message_id': worker_msg.message_id,
                        'correlation_id': worker_msg.correlation_id
                    }
                    
                self._trace(f"worker_{worker_msg.direction}", {
                    "worker": worker_msg.worker_url,
                    "correlation": worker_msg.correlation_id or "UNKNOWN",
                    "type": msg.get('type', 'message')
                })
                
            # Constroi pares de correlação
            inputs = {m.message_id: m for m in self.worker_messages 
                     if m.direction == 'page_to_worker'}
            outputs = [m for m in self.worker_messages 
                      if m.direction == 'worker_to_page']
            
            for out in outputs:
                if out.correlation_id:
                    # Procura input com mesmo correlation_id
                    for inp_id, inp in inputs.items():
                        if inp.correlation_id == out.correlation_id:
                            self.worker_message_pairs.append((inp_id, out.message_id))
                            break
                            
        except Exception as e:
            self._log_error("collect_worker_messages", e)
            
    async def _process_challenge(self, page: Page):
        """
        CORREÇÃO #3: Não assume entrada. Determina por evidência.
        Registra separadamente: input_candidate, input_source, processing_component, etc.
        """
        self._transition_state(ChallengeState.PROCESSING,
                              reason="Observando processamento do desafio")
        
        try:
            # CORREÇÃO #8: Acompanha campos pow_* específicos
            pow_fields_tracking = await page.evaluate('''() => {
                const track = {};
                const fields = ['pow_id', 'pow_nonce', 'pow_elapsed', 'pow_pauses', 'pow_data', 'pow_x'];
                fields.forEach(name => {
                    const el = document.getElementById(name) || document.getElementsByName(name)[0];
                    if (el) {
                        track[name] = {
                            initial_value: el.value || null,
                            element_type: el.type || el.tagName,
                            present: true
                        };
                    } else {
                        track[name] = { present: false };
                    }
                });
                return track;
            }''')
            
            self._trace("pow_fields_initial", pow_fields_tracking)
            
            # Determina input candidate por evidência
            input_candidate = None
            input_source = None
            input_evidence = []
            
            # Evidência 1: Worker input observado
            if self.worker_input_observed:
                input_candidate = self.worker_input_observed.get('content')
                input_source = "worker_input"
                input_evidence.append("observed_worker_message")
                
            # Evidência 2: Atributos data-* do captcha
            elif self.captcha_element_data:
                # Não assume qual campo, analisa todos
                for key, value in self.captcha_element_data.items():
                    if value and len(str(value)) > 10:  # Valor significativo
                        input_candidate = value
                        input_source = f"captcha_attribute:{key}"
                        input_evidence.append(f"attribute_{key}_present")
                        break
                        
            # Evidência 3: Campos ocultos no DOM
            else:
                hidden_data = await page.evaluate('''() => {
                    const inputs = document.querySelectorAll('input[type="hidden"]');
                    for (const inp of inputs) {
                        if (inp.value && inp.value.length > 20) {
                            return { name: inp.name || inp.id, value: inp.value };
                        }
                    }
                    return null;
                }''')
                
                if hidden_data:
                    input_candidate = hidden_data['value']
                    input_source = f"hidden_input:{hidden_data['name']}"
                    input_evidence.append("hidden_input_found")
                    
            if not input_candidate:
                self._log_unknown("Input do desafio não determinado",
                                "Nenhuma evidência de worker, atributo ou campo oculto")
                return False
                
            self.processing_data = {
                'input_candidate': input_candidate,
                'input_source': input_source,
                'input_evidence': input_evidence,
                'processing_component': 'Worker' if self.worker_input_observed else 'DOM/JavaScript',
                'timestamp': datetime.now().isoformat()
            }
            
            # Aguarda processamento observando mudanças
            start_time = time.time()
            max_wait = 120
            
            while time.time() - start_time < max_wait:
                current_pow = await page.evaluate('''() => {
                    const state = {};
                    const fields = ['pow_id', 'pow_nonce', 'pow_elapsed', 'pow_pauses', 'pow_data', 'pow_x'];
                    fields.forEach(name => {
                        const el = document.getElementById(name) || document.getElementsByName(name)[0];
                        if (el) state[name] = el.value;
                    });
                    return state;
                }''')
                
                # Detecta mudanças
                changes = {}
                for field, current in current_pow.items():
                    initial = pow_fields_tracking.get(field, {}).get('initial_value')
                    if current != initial and current:
                        changes[field] = {
                            'from': initial,
                            'to': current,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                if changes:
                    self.pow_fields_history.append({
                        'timestamp': datetime.now().isoformat(),
                        'changes': changes,
                        'full_state': current_pow
                    })
                    self._trace("pow_fields_changed", changes)
                    
                # Verifica se processamento completou
                filled_fields = [k for k, v in current_pow.items() if v and len(str(v)) > 0]
                
                # CORREÇÃO: Só marca RESULT_READY se observou mudanças reais
                if len(changes) > 0 and 'pow_nonce' in filled_fields:
                    self.processing_result = json.dumps({
                        'final_pow_state': current_pow,
                        'changes_observed': self.pow_fields_history,
                        'input_used': {
                            'candidate': input_candidate,
                            'source': input_source
                        },
                        'worker_involved': self.worker_input_observed is not None,
                        'output_source': 'DOM_fields_modified'
                    })
                    
                    self.current_challenge.processing_result = self.processing_result
                    self.current_challenge.processing_state = self.processing_data
                    
                    self._transition_state(ChallengeState.RESULT_READY,
                                          reason="Campos pow_* modificados observados após processamento",
                                          evidence=json.dumps({
                                              'fields_filled': filled_fields,
                                              'changes_count': len(self.pow_fields_history)
                                          }))
                    return True
                    
                await asyncio.sleep(0.5)
                
            self._log_unknown("Processamento não completou no tempo observado")
            return False
            
        except Exception as e:
            self._log_error("process_challenge", e)
            return False
            
    async def _identify_and_execute_submission(self, page: Page):
        """
        CORREÇÃO #9: Separa descoberta de execução. Identifica mecanismo real.
        """
        self._transition_state(ChallengeState.SUBMISSION,
                              reason="Analisando mecanismo de submissão")
        
        try:
            # Análise do mecanismo de submissão
            mechanism_analysis = await page.evaluate('''() => {
                const analysis = {
                    pow_captcha: null,
                    parent_form: null,
                    submit_buttons: [],
                    event_listeners: [],
                    javascript_handlers: []
                };
                
                const powCaptcha = document.getElementById('pow-captcha');
                if (powCaptcha) {
                    analysis.pow_captcha = {
                        tagName: powCaptcha.tagName,
                        hasForm: !!powCaptcha.closest('form'),
                        formId: powCaptcha.closest('form')?.id || null,
                        nextElement: powCaptcha.nextElementSibling?.tagName || null
                    };
                    
                    const parentForm = powCaptcha.closest('form');
                    if (parentForm) {
                        analysis.parent_form = {
                            id: parentForm.id,
                            action: parentForm.action,
                            method: parentForm.method,
                            submit_buttons: Array.from(parentForm.querySelectorAll('button[type="submit"], input[type="submit"]'))
                                .map(b => ({ id: b.id, text: b.innerText || b.value }))
                        };
                    }
                }
                
                // Procura botões que podem disparar submissão
                document.querySelectorAll('button, input[type="button"], a').forEach(btn => {
                    const onclick = btn.getAttribute('onclick') || '';
                    const hasListener = btn._eventListeners || false;
                    
                    if (btn.type === 'submit' || 
                        onclick.includes('submit') || 
                        onclick.includes('verify') ||
                        btn.className.includes('submit')) {
                        analysis.submit_buttons.push({
                            id: btn.id,
                            class: btn.className,
                            type: btn.type,
                            onclick: onclick.substring(0, 100),
                            text: (btn.innerText || btn.value || '').substring(0, 50)
                        });
                    }
                });
                
                return analysis;
            }''')
            
            # Registra análise sem executar
            self.current_challenge.submission_state = {
                'mechanism_analysis': mechanism_analysis,
                'identified_mechanism': None,
                'execution_attempted': False,
                'execution_method': None,
                'timestamp': datetime.now().isoformat()
            }
            
            self._trace("submission_mechanism_analysis", mechanism_analysis)
            
            # NÃO executa automaticamente - apenas identifica
            # A submissão real deve ser observada na rede ou no DOM
            
        except Exception as e:
            self._log_error("submission_analysis", e)
            
    async def _validate_with_server(self, page: Page):
        """
        CORREÇÃO #10: Validação baseada em evidências, não campos JSON genéricos.
        """
        self._transition_state(ChallengeState.SERVER_VALIDATION,
                              reason="Analisando respostas do servidor")
        
        try:
            await asyncio.sleep(2)
            
            validation_analysis = []
            
            for req_id, resp in self.network_responses.items():
                req = self.network_requests.get(req_id)
                
                analysis = {
                    'request_id': req_id,
                    'request': {
                        'url': req.url if req else 'UNKNOWN',
                        'method': req.method if req else 'UNKNOWN',
                        'classification': req.classification if req else 'UNKNOWN'
                    },
                    'response': {
                        'status': resp.status,
                        'url': resp.url,
                        'content_type': resp.content_type
                    },
                    'evidence': [],
                    'conclusion': 'UNKNOWN'
                }
                
                # Coleta evidências observáveis
                
                # 1. Status HTTP
                if resp.status >= 200 and resp.status < 300:
                    analysis['evidence'].append(f"http_success_{resp.status}")
                elif resp.status >= 400:
                    analysis['evidence'].append(f"http_error_{resp.status}")
                    
                # 2. Análise do corpo (sem assumir significado)
                if resp.parsed_body and isinstance(resp.parsed_body, dict):
                    body = resp.parsed_body
                    
                    # Registra campos presentes como evidência, não como prova
                    for key in ['success', 'valid', 'accepted', 'verified', 'token', 'session']:
                        if key in body:
                            value = body[key]
                            analysis['evidence'].append(f"field_{key}_present:{value}")
                            
                    # CORREÇÃO: Não assume que success=true significa aceito
                    # Apenas registra como evidência
                    if body.get('success') is True:
                        analysis['evidence'].append("field_success_is_true")
                    if body.get('success') is False:
                        analysis['evidence'].append("field_success_is_false")
                        
                # 3. Redirects
                if resp.status in [301, 302, 307, 308]:
                    location = resp.headers.get('location', '')
                    analysis['evidence'].append(f"redirect_to:{location}")
                    
                validation_analysis.append(analysis)
                
            # Determina conclusão baseada em múltiplas evidências correlacionadas
            # Não apenas em um campo JSON
            
            # Propor evidence suficiente para ACEITAÇÃO
            strong_acceptance = []
            for a in validation_analysis:
                # Múltiplas evidências positivas correlacionadas
                if (a['response']['status'] == 200 and 
                    'field_success_is_true' in a['evidence'] and
                    any('token' in e for e in a['evidence'])):
                    strong_acceptance.append(a)
                    
            # Procura evidence de REJEIÇÃO
            strong_rejection = []
            for a in validation_analysis:
                if (a['response']['status'] >= 400 or
                    ('field_success_is_false' in a['evidence'] and 
                     any('error' in e.lower() for e in a['evidence']))):
                    strong_rejection.append(a)
                    
            if strong_acceptance:
                best = strong_acceptance[0]
                self.current_challenge.validation_state = {
                    'conclusion': 'ACCEPTED',
                    'confidence': 'high',
                    'evidence': best['evidence'],
                    'request_id': best['request_id'],
                    'analysis': validation_analysis,
                    'timestamp': datetime.now().isoformat()
                }
                
                self._transition_state(ChallengeState.ACCEPTED,
                                      reason="Múltiplas evidências correlacionadas de aceitação",
                                      evidence=json.dumps(best['evidence']),
                                      request_id=best['request_id'])
                                      
            elif strong_rejection:
                best = strong_rejection[0]
                self.current_challenge.validation_state = {
                    'conclusion': 'REJECTED',
                    'confidence': 'high',
                    'evidence': best['evidence'],
                    'request_id': best['request_id'],
                    'analysis': validation_analysis,
                    'timestamp': datetime.now().isoformat()
                }
                
                self._transition_state(ChallengeState.REJECTED,
                                      reason="Evidências de rejeição do servidor",
                                      evidence=json.dumps(best['evidence']),
                                      request_id=best['request_id'])
            else:
                # Sem evidência suficiente
                self.current_challenge.validation_state = {
                    'conclusion': 'UNKNOWN',
                    'confidence': 'none',
                    'analysis': validation_analysis,
                    'reason': 'Nenhuma evidência suficiente para determinar aceitação/rejeição',
                    'timestamp': datetime.now().isoformat()
                }
                
                self._transition_state(ChallengeState.UNKNOWN,
                                      reason="Evidência insuficiente para validação")
                                      
        except Exception as e:
            self._log_error("validate_with_server", e)
            self._transition_state(ChallengeState.ERROR, reason=str(e))
            
    def _build_final_result(self) -> Dict:
        """
        CORREÇÃO #12: Deixa explícito confirmado vs inferido vs unknown.
        """
        
        # Determina status de cada componente
        def categorize_evidence(value, source):
            if value is None:
                return {"value": None, "status": "UNKNOWN", "source": None}
            if source and "observed" in source:
                return {"value": value, "status": "CONFIRMED", "source": source}
            if source and "inferred" in source:
                return {"value": value, "status": "INFERRED", "source": source}
            return {"value": value, "status": "PRESENT", "source": source}
        
        result = {
            "meta": {
                "principle": "observation → capture → correlation → evidence → conclusion",
                "timestamp": datetime.now().isoformat(),
                "final_state": self.current_state.value
            },
            "challenge": {
                "challenge_id": categorize_evidence(
                    self.current_challenge.challenge_id if self.current_challenge else None,
                    self.current_challenge.parameters.get('challenge_id_source') if self.current_challenge else None
                ),
                "session_id": categorize_evidence(
                    self.current_challenge.session_id if self.current_challenge else None,
                    self.current_challenge.parameters.get('session_id_source') if self.current_challenge else None
                ),
                "full_data": self.current_challenge.to_dict() if self.current_challenge else None
            },
            "processing": {
                "input": {
                    "candidate": categorize_evidence(
                        self.processing_data.get('input_candidate'),
                        self.processing_data.get('input_source')
                    ),
                    "evidence": self.processing_data.get('input_evidence', [])
                },
                "worker_input": categorize_evidence(
                    self.worker_input_observed,
                    "observed_worker_message" if self.worker_input_observed else None
                ),
                "worker_output": categorize_evidence(
                    self.worker_output_observed,
                    "observed_worker_message" if self.worker_output_observed else None
                ),
                "pow_field_changes": self.pow_fields_history,
                "result": categorize_evidence(
                    self.processing_result,
                    "observed_dom_changes" if self.pow_fields_history else None
                )
            },
            "submission": {
                "mechanism_analysis": self.current_challenge.submission_state if self.current_challenge else {},
                "executed": False,
                "status": "IDENTIFIED_NOT_EXECUTED"
            },
            "validation": {
                "conclusion": categorize_evidence(
                    self.current_challenge.validation_state.get('conclusion') if self.current_challenge else None,
                    "server_response_analysis" if self.current_challenge and self.current_challenge.validation_state else None
                ),
                "full_state": self.current_challenge.validation_state if self.current_challenge else {}
            },
            "state_machine": {
                "transitions": [t.to_dict() for t in self.state_transitions]
            },
            "evidence": {
                "scripts": {k: v.to_dict() for k, v in self.scripts.items()},
                "network_requests": {k: v.to_dict() for k, v in self.network_requests.items()},
                "network_responses": {k: v.to_dict() for k, v in self.network_responses.items()},
                "worker_messages": [m.to_dict() for m in self.worker_messages],
                "unmatched_responses": self._unmatched_responses
            },
            "unknowns": self.unknowns,
            "errors": self.errors,
            "event_trace": [e.to_dict() for e in self.event_trace]
        }
        
        self.final_result = result
        return result
        
    def _generate_text_report(self) -> str:
        """
        CORREÇÃO #13: Não assume SHA-256. Mostra status de evidência.
        """
        
        lines = []
        lines.append("=" * 80)
        lines.append("FILECRYPT EVIDENCE-BASED ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("1. CHALLENGE IDENTIFICATION")
        lines.append("-" * 40)
        if self.current_challenge:
            ch_id = self.current_challenge.challenge_id
            ch_source = self.current_challenge.parameters.get('challenge_id_source')
            sess_id = self.current_challenge.session_id
            sess_source = self.current_challenge.parameters.get('session_id_source')
            
            lines.append(f"Challenge ID: {ch_id or 'UNKNOWN'}")
            if ch_source:
                lines.append(f"  Source: {ch_source}")
            lines.append(f"Session ID: {sess_id or 'UNKNOWN'}")
            if sess_source:
                lines.append(f"  Source: {sess_source}")
        lines.append("")
        
        lines.append("2. PROCESSING (EVIDENCE-BASED)")
        lines.append("-" * 40)
        
        # Input
        if self.processing_data.get('input_candidate'):
            lines.append(f"Input Candidate: {str(self.processing_data['input_candidate'])[:50]}...")
            lines.append(f"  Source: {self.processing_data.get('input_source', 'UNKNOWN')}")
            lines.append(f"  Evidence: {self.processing_data.get('input_evidence', [])}")
        else:
            lines.append("Input: UNKNOWN - no evidence captured")
            
        # Algoritmo
        if self.pow_solver.observed_algorithm:
            lines.append(f"Algorithm: {self.pow_solver.observed_algorithm} (observed)")
        else:
            lines.append("Algorithm: UNKNOWN - not observed in flow")
            
        lines.append("")
        lines.append("Worker Communication:")
        lines.append(f"  Input Observed: {'YES' if self.worker_input_observed else 'NO'}")
        lines.append(f"  Output Observed: {'YES' if self.worker_output_observed else 'NO'}")
        lines.append(f"  Message Pairs: {len(self.worker_message_pairs)}")
        lines.append("")
        
        lines.append("PoW Field Changes:")
        for entry in self.pow_fields_history:
            lines.append(f"  [{entry['timestamp']}]")
            for field, change in entry.get('changes', {}).items():
                lines.append(f"    {field}: {str(change.get('from'))[:30]}... → {str(change.get('to'))[:30]}...")
        lines.append("")
        
        lines.append("3. VALIDATION")
        lines.append("-" * 40)
        if self.current_challenge and self.current_challenge.validation_state:
            val = self.current_challenge.validation_state
            conclusion = val.get('conclusion', 'UNKNOWN')
            confidence = val.get('confidence', 'none')
            lines.append(f"Conclusion: {conclusion}")
            lines.append(f"Confidence: {confidence}")
            lines.append(f"Evidence: {val.get('evidence', [])}")
        else:
            lines.append("Validation: NOT PERFORMED")
        lines.append("")
        
        lines.append("4. STATE MACHINE")
        lines.append("-" * 40)
        for t in self.state_transitions:
            lines.append(f"  {t.from_state.value} → {t.to_state.value}")
            lines.append(f"    Reason: {t.reason or 'N/A'}")
            if t.evidence:
                lines.append(f"    Evidence: {t.evidence[:80]}...")
        lines.append("")
        
        lines.append("5. UNKNOWN ELEMENTS")
        lines.append("-" * 40)
        for unk in self.unknowns:
            lines.append(f"  [{unk['timestamp']}] {unk['description']}")
        lines.append("")
        
        lines.append("6. ERRORS")
        lines.append("-" * 40)
        for err in self.errors:
            lines.append(f"  [{err['timestamp']}] {err['context']}: {err['error_type']}")
        lines.append("")
        
        return "\n".join(lines)
        
    async def run_processing(self, container_url: str):
        """Execução principal"""
        
        print("=" * 80)
        print("FILECRYPT EVIDENCE-BASED PROCESSOR")
        print("observation → capture → correlation → evidence → conclusion")
        print("=" * 80)
        
        self._trace("processing_start", {"url": container_url})
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=False,
                args=['--window-size=1400,900', '--disable-web-security']
            )
            
            context = await browser.new_context(
                viewport={'width': 1400, 'height': 900},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            
            # Pre-instrumentação
            await self._pre_instrument_workers(context)
            
            page = await context.new_page()
            
            # CORREÇÃO #5: Captura de rede com correlação confiável
            async def handle_route(route: Route, request: Request):
                self._request_counter += 1
                req_id = f"req_{self._request_counter}_{uuid.uuid4().hex[:8]}"
                
                # CORREÇÃO: Armazena mapeamento id(request) -> req_id
                self._request_id_map[id(request)] = req_id
                
                classification, confidence, evidences = self._classify_request(request)
                
                req = NetworkRequest(
                    request_id=req_id,
                    timestamp=datetime.now().isoformat(),
                    method=request.method,
                    url=request.url,
                    resource_type=request.resource_type,
                    headers=dict(request.headers),
                    classification=classification,
                    classification_confidence=confidence,
                    classification_evidence=evidences
                )
                
                try:
                    post_data = request.post_data
                    if post_data:
                        req.body = post_data[:10000] if len(post_data) > 10000 else post_data
                except:
                    pass
                    
                self.network_requests[req_id] = req
                await route.continue_()
                
            await page.route("**/*", handle_route)
            
            # Handler de response com CORREÇÃO #5
            async def handle_response(response: Response):
                try:
                    # CORREÇÃO: Usa id(response.request) para recuperar request_id
                    request_id = self._request_id_map.get(id(response.request))
                    
                    if not request_id:
                        # CORREÇÃO: Registra como não correlacionado, não cria ID falso
                        self._unmatched_responses.append({
                            'timestamp': datetime.now().isoformat(),
                            'response_url': response.url,
                            'status': response.status,
                            'reason': 'request_object_not_in_map'
                        })
                        self._log_unknown(f"Response não correlacionada: {response.url[:60]}")
                        return
                        
                    # Lê body
                    body = None
                    try:
                        body_text = await response.text()
                        body = body_text[:50000] if len(body_text) > 50000 else body_text
                    except:
                        pass
                        
                    resp = NetworkResponse(
                        request_id=request_id,
                        timestamp=datetime.now().isoformat(),
                        status=response.status,
                        url=response.url,
                        content_type=response.headers.get('content-type'),
                        headers=dict(response.headers),
                        size=len(body) if body else 0,
                        body=body
                    )
                    
                    # Parseia JSON se possível
                    if body:
                        try:
                            resp.parsed_body = json.loads(body)
                        except:
                            pass
                            
                    self.network_responses[request_id] = resp
                    
                    # Atualiza classificação com evidência da resposta
                    await self._update_classification_with_evidence(request_id)
                    
                except Exception as e:
                    self._log_error("handle_response", e)
                    
            page.on("response", lambda r: asyncio.create_task(handle_response(r)))
            
            try:
                # Navegação
                await page.goto(container_url, wait_until='networkidle')
                self._trace("page_loaded", {"url": page.url})
                
                # Captura scripts
                await self._capture_scripts(page)
                
                # Descobre desafio
                challenge_found = await self._discover_challenge(page)
                
                if not challenge_found:
                    print("AVISO: Desafio não encontrado")
                    return
                    
                # Coleta mensagens Worker
                await self._collect_worker_messages(page)
                
                # Processa desafio (observação, não execução forçada)
                await self._process_challenge(page)
                
                # Analisa submissão (não executa)
                await self._identify_and_execute_submission(page)
                
                # Valida com servidor
                await self._validate_with_server(page)
                
                # Coleta finais
                await self._collect_worker_messages(page)
                
                # Cookies
                cookies = await context.cookies()
                self.current_session = SessionContext(
                    session_id=self.current_challenge.session_id if self.current_challenge else None,
                    cookies=cookies
                )
                
            except Exception as e:
                self._log_error("run_processing", e)
                self._transition_state(ChallengeState.ERROR, reason=str(e))
                
            finally:
                # Resultado
                result = self._build_final_result()
                
                with open('filecrypt_flow_analysis.json', 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=str)
                    
                with open('filecrypt_flow_analysis.txt', 'w', encoding='utf-8') as f:
                    f.write(self._generate_text_report())
                    
                print("\n" + "=" * 80)
                print("ANÁLISE CONCLUÍDA")
                print("=" * 80)
                print(f"Estado Final: {self.current_state.value}")
                print(f"Challenge ID: {self.current_challenge.challenge_id if self.current_challenge else 'N/A'}")
                print(f"Worker Input: {'SIM' if self.worker_input_observed else 'NÃO'}")
                print(f"Worker Output: {'SIM' if self.worker_output_observed else 'NÃO'}")
                print(f"Unknowns: {len(self.unknowns)}")
                print(f"Unmatched Responses: {len(self._unmatched_responses)}")
                print(f"Arquivos: filecrypt_flow_analysis.json, filecrypt_flow_analysis.txt")
                
                await browser.close()
                
        return self.final_result


def main():
    parser = argparse.ArgumentParser(description='FileCrypt Evidence-Based Processor')
    parser.add_argument('url', help='URL do container FileCrypt')
    args = parser.parse_args()
    
    processor = FileCryptProcessor()
    
    try:
        asyncio.run(processor.run_processing(args.url))
    except KeyboardInterrupt:
        print("\nInterrompido")
        sys.exit(1)
    except Exception as e:
        print(f"\nErro fatal: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()