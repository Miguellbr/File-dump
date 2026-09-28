#!/usr/bin/env python3
"""
FileCrypt Reverse Engineering Tool - file-rev.py
Ferramenta automatizada de processamento do fluxo de verificação do FileCrypt.

Arquitetura: URL → DESCOBERTA → DESAFIO → SESSÃO → PROCESSAMENTO → ENVIO → VALIDAÇÃO → RESULTADO

CORREÇÕES:
1. Worker instrumentado ANTES da navegação
2. Processamento real implementado (PoW solver)
3. Validação analisa conteúdo da resposta
4. Request/Response correlacionados por ID único
5. Componente de processamento ativo, não apenas observação
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
    classification: str = "OTHER"
    related_challenge: Optional[str] = None
    related_session: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NetworkResponse:
    """Response de rede capturado"""
    request_id: str  # Mesmo ID do request para correlação
    timestamp: str
    status: int
    url: str
    content_type: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    size: int = 0
    body: Optional[str] = None
    parsed_body: Optional[Dict] = None  # Body parseado quando possível
    
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
    """Transição de estado"""
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
    Solver de Proof of Work.
    Implementação do algoritmo de processamento do desafio.
    """
    
    def __init__(self):
        self.attempts: List[Dict] = []
        self.solution: Optional[Dict] = None
        
    def solve_sha256(self, challenge_data: str, difficulty: int = 4) -> Optional[Dict]:
        """
        Resolve desafio PoW usando SHA-256.
        difficulty = número de zeros hexadecimais no início do hash.
        """
        start_time = time.time()
        nonce = 0
        target = "0" * difficulty
        
        print(f"[PoW] Iniciando mineração - Difficulty: {difficulty}")
        print(f"[PoW] Challenge data: {challenge_data[:50]}...")
        
        while True:
            # Constroi payload
            payload = f"{challenge_data}{nonce}"
            hash_result = hashlib.sha256(payload.encode()).hexdigest()
            
            # Verifica dificuldade
            if hash_result.startswith(target):
                elapsed = time.time() - start_time
                solution = {
                    "nonce": nonce,
                    "hash": hash_result,
                    "payload": payload,
                    "difficulty": difficulty,
                    "attempts": nonce + 1,
                    "elapsed_time": elapsed,
                    "timestamp": datetime.now().isoformat()
                }
                self.solution = solution
                self.attempts.append({
                    "nonce": nonce,
                    "hash": hash_result,
                    "success": True
                })
                print(f"[PoW] Solução encontrada em {elapsed:.3f}s - Nonce: {nonce}")
                return solution
                
            nonce += 1
            
            # Registra tentativas a cada 10000
            if nonce % 10000 == 0:
                elapsed = time.time() - start_time
                print(f"[PoW] {nonce} tentativas... ({elapsed:.1f}s)")
                
            # Timeout de segurança
            if time.time() - start_time > 300:  # 5 minutos
                print("[PoW] Timeout - Não foi possível encontrar solução")
                return None
                
    def solve_with_pattern(self, pattern: str, prefix: str = "") -> Optional[Dict]:
        """
        Resolve buscando por padrão específico no hash.
        """
        start_time = time.time()
        nonce = 0
        
        while True:
            payload = f"{prefix}{nonce}"
            hash_result = hashlib.sha256(payload.encode()).hexdigest()
            
            if pattern in hash_result:
                return {
                    "nonce": nonce,
                    "hash": hash_result,
                    "payload": payload,
                    "pattern": pattern,
                    "elapsed_time": time.time() - start_time
                }
                
            nonce += 1
            
            if time.time() - start_time > 300:
                return None


class FileCryptProcessor:
    """
    Processador completo do FileCrypt CAPTCHA.
    Implementa fluxo ativo: DESCoberta → PROCESSAMENTO → SUBMISSÃO → VALIDAÇÃO
    """
    
    def __init__(self):
        # Estruturas de dados
        self.scripts: Dict[str, ScriptInfo] = {}
        self.network_requests: Dict[str, NetworkRequest] = {}
        self.network_responses: Dict[str, NetworkResponse] = {}
        self.worker_messages: List[WorkerMessage] = []
        self.worker_message_pairs: List[Tuple[str, str]] = []
        self.event_trace: List[EventTraceEntry] = []
        self.state_transitions: List[StateTransition] = []
        
        # Contextos
        self.current_challenge: Optional[Challenge] = None
        self.current_session: Optional[SessionContext] = None
        
        # Estado
        self.current_state: ChallengeState = ChallengeState.INIT
        self.scripts_discovered: List[str] = []
        self.pow_fields_history: List[Dict] = []
        self.validation_candidates: List[Dict] = []
        self.errors: List[Dict] = []
        self.unknowns: List[str] = []
        
        # Dados de processamento
        self.server_input: Dict[str, Any] = {}
        self.client_state: Dict[str, Any] = {}
        self.processing_data: Dict[str, Any] = {}
        self.processing_result: Optional[str] = None
        self.server_validation: Dict[str, Any] = {}
        
        # Elementos DOM
        self.captcha_element_data: Dict[str, Any] = {}
        self.form_fields_log: List[Dict] = []
        self.dom_mutations: List[Dict] = []
        
        # Componentes ativos
        self.pow_solver = PoWSolver()
        
        # Request ID counter para correlação
        self._request_counter = 0
        self._request_map: Dict[str, str] = {}  # Maps playwright request to our ID
        
        # Resultado final
        self.final_result: Optional[Dict] = None
        
    def _get_request_id(self, request: Request) -> str:
        """Gera ID único consistente para request"""
        self._request_counter += 1
        req_id = f"req_{self._request_counter}_{uuid.uuid4().hex[:8]}"
        self._request_map[id(request)] = req_id
        return req_id
        
    def _get_response_id(self, response: Response) -> str:
        """Recupera ID do request correspondente"""
        return self._request_map.get(id(response.request), f"req_unknown_{uuid.uuid4().hex[:8]}")
        
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
        """Transiciona a máquina de estados"""
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
        """Registra erro de forma robusta"""
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
        
    def _log_unknown(self, description: str):
        """Registra algo que não pôde ser determinado"""
        self.unknowns.append({
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "current_state": self.current_state.value
        })
        self._trace("unknown", {"description": description})
        
    def _classify_request(self, request: Request) -> str:
        """Classifica request baseado em evidências"""
        url = request.url.lower()
        resource_type = request.resource_type
        
        if 'worker' in url or 'worker' in resource_type:
            return "WORKER"
        if any(x in url for x in ['captcha', 'challenge', 'pow']):
            return "CHALLENGE"
        if any(x in url for x in ['session', 'sess']):
            return "SESSION"
        if any(x in url for x in ['validate', 'verify', 'check', 'submit', 'api']):
            return "VALIDATION_CANDIDATE"
        if resource_type in ['script', 'javascript']:
            return "SCRIPT"
        if 'process' in url:
            return "PROCESSING"
            
        return "OTHER"
        
    def _compute_sha256(self, content: str) -> str:
        """Calcula SHA-256 do conteúdo"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
        
    async def _pre_instrument_workers(self, context: BrowserContext):
        """
        CORREÇÃO #1: Instrumenta Workers ANTES da navegação.
        Usa evaluate_on_new_document para injetar código antes de qualquer script rodar.
        """
        
        # Injeta instrumentação em todas as páginas novas
        await context.add_init_script("""
            // Intercepta Worker globalmente
            (function() {
                const OriginalWorker = window.Worker;
                window._workerMessages = [];
                window._workerUrls = [];
                
                window.Worker = function(url) {
                    const workerId = 'worker_' + Math.random().toString(36).substr(2, 9);
                    window._workerUrls.push({id: workerId, url: url.toString(), timestamp: new Date().toISOString()});
                    
                    const worker = new OriginalWorker(url);
                    worker._workerId = workerId;
                    worker._workerUrl = url.toString();
                    
                    // Intercepta postMessage
                    const originalPostMessage = worker.postMessage.bind(worker);
                    worker.postMessage = function(message, transfer) {
                        const msg = {
                            id: 'msg_' + Math.random().toString(36).substr(2, 9),
                            direction: 'to_worker',
                            workerId: workerId,
                            workerUrl: worker._workerUrl,
                            timestamp: new Date().toISOString(),
                            data: message
                        };
                        window._workerMessages.push(msg);
                        
                        // Tenta estabelecer correlação
                        if (message && typeof message === 'object') {
                            msg.correlationId = message.id || message.requestId || null;
                        }
                        
                        return originalPostMessage(message, transfer);
                    };
                    
                    // Intercepta onmessage
                    worker.addEventListener('message', function(event) {
                        const msg = {
                            id: 'msg_' + Math.random().toString(36).substr(2, 9),
                            direction: 'from_worker',
                            workerId: workerId,
                            workerUrl: worker._workerUrl,
                            timestamp: new Date().toISOString(),
                            data: event.data
                        };
                        
                        // Tenta correlacionar com input
                        if (event.data && typeof event.data === 'object') {
                            msg.correlationId = event.data.id || event.data.requestId || 
                                               event.data.correlationId || null;
                        }
                        
                        window._workerMessages.push(msg);
                    });
                    
                    // Intercepta erros
                    worker.addEventListener('error', function(error) {
                        window._workerMessages.push({
                            id: 'msg_err_' + Math.random().toString(36).substr(2, 9),
                            direction: 'worker_error',
                            workerId: workerId,
                            workerUrl: worker._workerUrl,
                            timestamp: new Date().toISOString(),
                            error: error.message || 'Worker error'
                        });
                    });
                    
                    return worker;
                };
                
                // Preserva prototype
                window.Worker.prototype = OriginalWorker.prototype;
                
                console.log('[FileRev Instrumentation] Worker interception active');
            })();
        """)
        
        self._trace("worker_pre_instrumentation", {"status": "injected"})
        
    async def _discover_challenge(self, page: Page):
        """Descobre automaticamente o desafio"""
        self._transition_state(ChallengeState.CHALLENGE_DISCOVERY, 
                              reason="Iniciando descoberta do desafio")
        
        try:
            # Aguarda carregamento
            await page.wait_for_load_state('networkidle')
            
            # Procura pelo componente #pow-captcha
            captcha_exists = await page.evaluate('''() => {
                return document.getElementById('pow-captcha') !== null;
            }''')
            
            if not captcha_exists:
                self._log_unknown("Elemento #pow-captcha não encontrado")
                return False
                
            # Extrai todos os atributos data-*
            captcha_data = await page.evaluate('''() => {
                const el = document.getElementById('pow-captcha');
                if (!el) return null;
                
                const data = {};
                for (const attr of el.attributes) {
                    if (attr.name.startsWith('data-')) {
                        data[attr.name] = attr.value;
                    }
                }
                return data;
            }''')
            
            self.captcha_element_data = captcha_data or {}
            
            # Extrai campos pow_*
            pow_fields = await page.evaluate('''() => {
                const fields = {};
                document.querySelectorAll('[id^="pow_"], [name^="pow_"]').forEach(el => {
                    const key = el.id || el.name;
                    fields[key] = {
                        value: el.value || null,
                        type: el.type || el.tagName.toLowerCase(),
                        attributes: {}
                    };
                    for (const attr of el.attributes) {
                        fields[key].attributes[attr.name] = attr.value;
                    }
                });
                return fields;
            }''')
            
            # Cria o desafio
            self.current_challenge = Challenge(
                challenge_id=captcha_data.get('data-session') if captcha_data else None,
                session_id=captcha_data.get('data-session') if captcha_data else None,
                payload=json.dumps(captcha_data) if captcha_data else None,
                parameters={
                    'data_worker': captcha_data.get('data-worker'),
                    'data_ext': captcha_data.get('data-ext'),
                    'data_sig': captcha_data.get('data-sig'),
                    'data_px': captcha_data.get('data-px'),
                    'data_state': captcha_data.get('data-state'),
                    'pow_fields_initial': pow_fields
                },
                source="DOM#pow-captcha",
                created_at=datetime.now().isoformat()
            )
            
            # Armazena server input
            self.server_input = {
                'captcha_attributes': captcha_data,
                'pow_fields': pow_fields,
                'timestamp': datetime.now().isoformat()
            }
            
            self.client_state = {
                'captcha_attributes': captcha_data,
                'pow_fields_initial': pow_fields,
                'timestamp': datetime.now().isoformat()
            }
            
            self._transition_state(ChallengeState.CHALLENGE_ACQUIRED,
                                  reason="Desafio identificado no DOM",
                                  evidence=json.dumps(captcha_data))
            
            self._trace("challenge_discovered", {
                "challenge_id": self.current_challenge.challenge_id,
                "attributes": captcha_data,
                "pow_fields": pow_fields
            })
            
            return True
            
        except Exception as e:
            self._log_error("discover_challenge", e)
            self._transition_state(ChallengeState.ERROR, reason=str(e))
            return False
            
    async def _process_challenge(self, page: Page):
        """
        CORREÇÃO #2: Implementa processamento REAL do desafio.
        Não apenas observa - resolve o PoW ativamente.
        """
        self._transition_state(ChallengeState.PROCESSING,
                              reason="Iniciando processamento ativo do desafio")
        
        try:
            # Extrai dados necessários do desafio
            challenge_data = self.current_challenge.parameters.get('data_px') or \
                           self.current_challenge.parameters.get('data_sig') or \
                           self.current_challenge.challenge_id or \
                           "unknown_challenge"
                           
            # Tenta determinar dificuldade
            difficulty = 4  # Padrão
            if self.current_challenge.parameters.get('data_ext'):
                # Tenta extrair difficulty do data-ext
                ext = self.current_challenge.parameters['data_ext']
                match = re.search(r'difficulty["\\']?\\s*[:=]\\s*(\\d+)', str(ext))
                if match:
                    difficulty = int(match.group(1))
                    
            print(f"[PROCESSING] Challenge data: {challenge_data[:50]}...")
            print(f"[PROCESSING] Difficulty: {difficulty}")
            
            # Executa solver
            solution = self.pow_solver.solve_sha256(challenge_data, difficulty)
            
            if solution:
                self.processing_result = json.dumps(solution)
                self.processing_data = {
                    'algorithm': 'SHA-256',
                    'difficulty': difficulty,
                    'solution': solution,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Preenche campos no DOM se existirem
                await page.evaluate(f'''(solution) => {{
                    // Preenche campos pow_* se existirem
                    const powHash = document.getElementById('pow_hash');
                    const powNonce = document.getElementById('pow_nonce');
                    const powData = document.getElementById('pow_data');
                    
                    if (powHash) powHash.value = solution.hash;
                    if (powNonce) powNonce.value = solution.nonce.toString();
                    if (powData) powData.value = solution.payload;
                    
                    // Dispara eventos de mudança
                    [powHash, powNonce, powData].forEach(el => {{
                        if (el) {{
                            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                        }}
                    }});
                    
                    return {{
                        powHashFilled: !!powHash?.value,
                        powNonceFilled: !!powNonce?.value,
                        powDataFilled: !!powData?.value
                    }};
                }}''', solution)
                
                self._transition_state(ChallengeState.RESULT_READY,
                                      reason="PoW resolvido com sucesso",
                                      evidence=json.dumps(solution))
                return True
            else:
                self._log_unknown("Não foi possível resolver o desafio PoW")
                return False
                
        except Exception as e:
            self._log_error("process_challenge", e)
            return False
            
    async def _identify_and_execute_submission(self, page: Page):
        """Identifica e executa submissão do resultado"""
        self._transition_state(ChallengeState.SUBMISSION,
                              reason="Identificando submissão")
        
        try:
            # Procura por form/button de submit
            submission_info = await page.evaluate('''() => {
                const info = {
                    forms: [],
                    buttons: [],
                    powForm: null
                };
                
                // Procura forms
                document.querySelectorAll('form').forEach((form, i) => {
                    info.forms.push({
                        index: i,
                        action: form.action,
                        method: form.method,
                        id: form.id,
                        class: form.className,
                        hasPowFields: !!form.querySelector('[id^="pow_"], [name^="pow_"]')
                    });
                });
                
                // Procura botões
                document.querySelectorAll('button, input[type="submit"]').forEach((btn, i) => {
                    const isSubmit = btn.type === 'submit' || 
                                     btn.tagName.toLowerCase() === 'button' ||
                                     btn.onclick || 
                                     btn.className.includes('submit') ||
                                     btn.id.includes('submit');
                                     
                    if (isSubmit) {
                        info.buttons.push({
                            index: i,
                            id: btn.id,
                            class: btn.className,
                            text: btn.innerText || btn.value,
                            type: btn.type
                        });
                    }
                });
                
                // Procura form específico do pow
                const powCaptcha = document.getElementById('pow-captcha');
                if (powCaptcha) {
                    const parentForm = powCaptcha.closest('form');
                    if (parentForm) {
                        info.powForm = {
                            action: parentForm.action,
                            method: parentForm.method,
                            id: parentForm.id
                        };
                    }
                }
                
                return info;
            }''')
            
            self.current_challenge.submission_state = {
                "discovery": submission_info,
                "timestamp": datetime.now().isoformat()
            }
            
            self._trace("submission_identified", submission_info)
            
            # Tenta submeter automaticamente
            if submission_info.get('powForm') or submission_info['forms']:
                # Clica no botão de submit ou submete o form
                submitted = await page.evaluate('''() => {
                    const form = document.getElementById('pow-captcha')?.closest('form');
                    if (form) {
                        form.dispatchEvent(new Event('submit', { bubbles: true }));
                        // Ou tenta click em submit button
                        const submitBtn = form.querySelector('button[type="submit"], input[type="submit"]');
                        if (submitBtn) {
                            submitBtn.click();
                            return { method: 'button_click', id: submitBtn.id };
                        }
                        return { method: 'form_submit', id: form.id };
                    }
                    
                    // Fallback: procura qualquer botão de submit
                    const btn = document.querySelector('button[type="submit"], .submit, #submit');
                    if (btn) {
                        btn.click();
                        return { method: 'fallback_click', id: btn.id };
                    }
                    
                    return null;
                }''')
                
                if submitted:
                    self.current_challenge.submission_state['execution'] = submitted
                    self._trace("submission_executed", submitted)
                    
                # Aguarda resposta do servidor
                await asyncio.sleep(2)
                
        except Exception as e:
            self._log_error("submission", e)
            
    async def _validate_with_server(self, page: Page):
        """
        CORREÇÃO #3: Validação analisa conteúdo da resposta, não só status HTTP.
        """
        self._transition_state(ChallengeState.SERVER_VALIDATION,
                              reason="Validando com servidor")
        
        try:
            # Aguarda requests de validação
            await asyncio.sleep(3)
            
            # Analisa requests de validação candidatos
            validation_requests = []
            for req_id, req in self.network_requests.items():
                if req.classification in ["VALIDATION_CANDIDATE", "SUBMISSION", "API"]:
                    resp = self.network_responses.get(req_id)
                    if resp:
                        validation_requests.append({
                            "request": req,
                            "response": resp
                        })
                        
            # Analisa cada candidato profundamente
            for candidate in validation_requests:
                req = candidate["request"]
                resp = candidate["response"]
                
                # Analisa corpo da resposta
                is_accepted = False
                evidence = {
                    "status": resp.status,
                    "content_type": resp.content_type,
                    "url": resp.url
                }
                
                # Parseia JSON se possível
                parsed_body = None
                if resp.body:
                    try:
                        parsed_body = json.loads(resp.body)
                        evidence["parsed_json"] = parsed_body
                    except:
                        evidence["body_sample"] = resp.body[:500] if resp.body else None
                        
                # Critérios de aceitação baseados em evidências
                if parsed_body:
                    # Verifica campos comuns de sucesso
                    if any([
                        parsed_body.get('success') is True,
                        parsed_body.get('status') == 'ok',
                        parsed_body.get('valid') is True,
                        parsed_body.get('result') == 'success',
                        'token' in parsed_body,
                        'session' in parsed_body and parsed_body.get('error') is None
                    ]):
                        is_accepted = True
                        evidence["success_indicator"] = "json_field"
                        
                # Verifica redirects de sucesso
                if resp.status in [301, 302, 307, 308]:
                    location = resp.headers.get('location', '')
                    if not any(x in location.lower() for x in ['error', 'fail', 'invalid']):
                        is_accepted = True
                        evidence["success_indicator"] = "redirect"
                        
                # Verifica cookies de sessão
                if self.current_session:
                    for cookie in self.current_session.cookies:
                        if 'session' in cookie.get('name', '').lower() and cookie.get('value'):
                            evidence["session_cookie"] = cookie['name']
                            
                # Registra validação
                self.current_challenge.validation_state = {
                    "request": req.to_dict(),
                    "response": resp.to_dict(),
                    "parsed_body": parsed_body,
                    "result": "ACCEPTED" if is_accepted else "REJECTED",
                    "evidence": evidence,
                    "timestamp": datetime.now().isoformat()
                }
                
                if is_accepted:
                    self._transition_state(ChallengeState.ACCEPTED,
                                          reason="Servidor aceitou - evidência na resposta",
                                          evidence=json.dumps(evidence),
                                          request_id=req.request_id,
                                          response_id=resp.request_id)
                    return
                else:
                    # Se encontrou candidato mas foi rejeitado
                    if parsed_body and parsed_body.get('success') is False:
                        self._transition_state(ChallengeState.REJECTED,
                                              reason="Servidor rejeitou explicitamente",
                                              evidence=json.dumps(evidence),
                                              request_id=req.request_id,
                                              response_id=resp.request_id)
                        return
                        
            # Se não encontrou validação clara
            self._transition_state(ChallengeState.UNKNOWN,
                                  reason="Não foi possível determinar validação do servidor")
                                  
        except Exception as e:
            self._log_error("validate_with_server", e)
            self._transition_state(ChallengeState.ERROR, reason=str(e))
            
    def _build_final_result(self) -> Dict:
        """Constrói objeto final estruturado"""
        
        result = {
            "challenge": self.current_challenge.to_dict() if self.current_challenge else None,
            "session": self.current_session.to_dict() if self.current_session else None,
            "processing": {
                "server_input": self.server_input,
                "client_state": self.client_state,
                "processing_data": self.processing_data,
                "processing_result": self.processing_result,
                "pow_attempts": self.pow_solver.attempts,
                "pow_solution": self.pow_solver.solution
            },
            "submission": self.current_challenge.submission_state if self.current_challenge else {},
            "validation": self.current_challenge.validation_state if self.current_challenge else {},
            "final_state": {
                "current_state": self.current_state.value,
                "transitions": [t.to_dict() for t in self.state_transitions]
            },
            "evidence": {
                "scripts": {k: v.to_dict() for k, v in self.scripts.items()},
                "network_requests": {k: v.to_dict() for k, v in self.network_requests.items()},
                "network_responses": {k: v.to_dict() for k, v in self.network_responses.items()},
                "worker_messages": [m.to_dict() for m in self.worker_messages],
                "dom_mutations": self.dom_mutations,
                "pow_fields_history": self.pow_fields_history
            },
            "errors": self.errors,
            "unknowns": self.unknowns,
            "event_trace": [e.to_dict() for e in self.event_trace]
        }
        
        self.final_result = result
        return result
        
    def _generate_text_report(self) -> str:
        """Gera relatório em formato TXT"""
        
        lines = []
        lines.append("=" * 80)
        lines.append("FILECRYPT FLOW ANALYSIS REPORT")
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("1. CONFIGURAÇÃO")
        lines.append("-" * 40)
        lines.append(f"Estado Final: {self.current_state.value}")
        lines.append(f"Total de Transições: {len(self.state_transitions)}")
        lines.append("")
        
        lines.append("2. DESAFIO")
        lines.append("-" * 40)
        if self.current_challenge:
            lines.append(f"Challenge ID: {self.current_challenge.challenge_id or 'UNKNOWN'}")
            lines.append(f"Session ID: {self.current_challenge.session_id or 'UNKNOWN'}")
            lines.append(f"Source: {self.current_challenge.source or 'UNKNOWN'}")
            lines.append(f"Parameters: {json.dumps(self.current_challenge.parameters, indent=2)}")
        else:
            lines.append("Desafio não identificado")
        lines.append("")
        
        lines.append("3. PROCESSAMENTO (ATIVO)")
        lines.append("-" * 40)
        if self.pow_solver.solution:
            sol = self.pow_solver.solution
            lines.append(f"Algorithm: SHA-256")
            lines.append(f"Difficulty: {sol.get('difficulty', 'N/A')}")
            lines.append(f"Nonce: {sol.get('nonce', 'N/A')}")
            lines.append(f"Hash: {sol.get('hash', 'N/A')}")
            lines.append(f"Elapsed Time: {sol.get('elapsed_time', 'N/A'):.3f}s")
            lines.append(f"Attempts: {sol.get('attempts', 'N/A')}")
        else:
            lines.append("Processamento não concluído")
        lines.append("")
        
        lines.append("4. VALIDAÇÃO DO SERVIDOR")
        lines.append("-" * 40)
        if self.current_challenge and self.current_challenge.validation_state:
            val = self.current_challenge.validation_state
            lines.append(f"Result: {val.get('result', 'UNKNOWN')}")
            lines.append(f"Evidence: {json.dumps(val.get('evidence', {}), indent=2)}")
        else:
            lines.append("Validação não realizada")
        lines.append("")
        
        lines.append("5. MÁQUINA DE ESTADOS")
        lines.append("-" * 40)
        for t in self.state_transitions:
            lines.append(f"  {t.from_state.value} → {t.to_state.value}")
            lines.append(f"    Reason: {t.reason or 'N/A'}")
        lines.append("")
        
        lines.append("6. NETWORK")
        lines.append("-" * 40)
        lines.append(f"Total Requests: {len(self.network_requests)}")
        lines.append(f"Total Responses: {len(self.network_responses)}")
        for req_id, req in list(self.network_requests.items())[:10]:
            resp = self.network_responses.get(req_id)
            status = resp.status if resp else "N/A"
            lines.append(f"  [{req.method}] {status} {req.url[:60]}...")
        lines.append("")
        
        lines.append("7. WORKER MESSAGES")
        lines.append("-" * 40)
        lines.append(f"Total: {len(self.worker_messages)}")
        for msg in self.worker_messages[:10]:
            lines.append(f"  [{msg.direction}] {msg.timestamp}")
        lines.append("")
        
        lines.append("8. ERROS")
        lines.append("-" * 40)
        if self.errors:
            for err in self.errors:
                lines.append(f"  [{err['timestamp']}] {err['context']}: {err['error_type']}")
        else:
            lines.append("Nenhum erro")
        lines.append("")
        
        lines.append("9. UNKNOWN")
        lines.append("-" * 40)
        if self.unknowns:
            for unk in self.unknowns:
                lines.append(f"  - {unk['description']}")
        else:
            lines.append("Nenhum elemento desconhecido")
        lines.append("")
        
        return "\n".join(lines)
        
    async def run_processing(self, container_url: str):
        """
        Execução principal do fluxo completo de PROCESSAMENTO ATIVO.
        
        Fluxo corrigido:
        PRE-INSTRUMENTAÇÃO → NAVEGAÇÃO → DESCOBERTA → PROCESSAMENTO → SUBMISSÃO → VALIDAÇÃO
        """
        
        print("=" * 80)
        print("FILECRYPT ACTIVE PROCESSOR")
        print("Zero suposições - Apenas evidências observáveis")
        print("CORREÇÕES: Pre-instrumentação | Processamento Ativo | Validação Real")
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
            
            # CORREÇÃO #1: Pre-instrumentação antes de criar página
            await self._pre_instrument_workers(context)
            
            page = await context.new_page()
            
            # Configura captura de rede
            async def handle_route(route: Route, request: Request):
                """Intercepta requests para correlação"""
                req_id = self._get_request_id(request)
                
                req = NetworkRequest(
                    request_id=req_id,
                    timestamp=datetime.now().isoformat(),
                    method=request.method,
                    url=request.url,
                    resource_type=request.resource_type,
                    headers=dict(request.headers),
                    classification=self._classify_request(request)
                )
                
                # Tenta obter body
                try:
                    post_data = request.post_data
                    if post_data:
                        req.body = post_data[:10000] if len(post_data) > 10000 else post_data
                except:
                    pass
                    
                self.network_requests[req_id] = req
                self._trace("request_captured", {"id": req_id, "url": request.url[:80]})
                
                await route.continue_()
                
            # Configura interceptação
            await page.route("**/*", handle_route)
            
            # Handler de response
            async def handle_response(response: Response):
                """CORREÇÃO #4: Usa mesmo ID do request"""
                try:
                    req_id = self._get_response_id(response)
                    
                    # Lê body se possível
                    body = None
                    try:
                        if response.headers.get('content-length', '0') != '0':
                            body_text = await response.text()
                            body = body_text[:50000] if len(body_text) > 50000 else body_text
                    except:
                        pass
                        
                    resp = NetworkResponse(
                        request_id=req_id,
                        timestamp=datetime.now().isoformat(),
                        status=response.status,
                        url=response.url,
                        content_type=response.headers.get('content-type'),
                        headers=dict(response.headers),
                        size=len(body) if body else 0,
                        body=body
                    )
                    
                    self.network_responses[req_id] = resp
                    self._trace("response_captured", {
                        "id": req_id,
                        "status": response.status,
                        "url": response.url[:80]
                    })
                    
                except Exception as e:
                    self._log_error("handle_response", e)
                    
            page.on("response", lambda r: asyncio.create_task(handle_response(r)))
            
            try:
                # Navegação
                self._trace("navigation_start", {"url": container_url})
                await page.goto(container_url, wait_until='networkidle')
                self._trace("navigation_complete", {"url": page.url})
                
                # Coleta mensagens do Worker já capturadas
                await self._collect_worker_messages(page)
                
                # Descobre desafio
                challenge_found = await self._discover_challenge(page)
                
                if not challenge_found:
                    print("AVISO: Desafio não encontrado na página")
                    self._log_unknown("Desafio não encontrado na página inicial")
                    return
                    
                # CORREÇÃO #2: Processa o desafio ativamente (não apenas observa)
                processing_success = await self._process_challenge(page)
                
                if not processing_success:
                    print("ERRO: Falha no processamento do desafio")
                    return
                    
                # Submissão
                await self._identify_and_execute_submission(page)
                
                # CORREÇÃO #3: Validação analisando resposta real
                await self._validate_with_server(page)
                
                # Coleta dados finais
                await self._collect_worker_messages(page)
                
                # Coleta cookies
                cookies = await context.cookies()
                if self.current_session:
                    self.current_session.cookies = cookies
                else:
                    self.current_session = SessionContext(cookies=cookies)
                    
            except Exception as e:
                self._log_error("run_processing", e)
                self._transition_state(ChallengeState.ERROR, reason=str(e))
                
            finally:
                # Resultado final
                result = self._build_final_result()
                
                # Salva relatórios
                with open('filecrypt_flow_analysis.json', 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, default=str)
                    
                with open('filecrypt_flow_analysis.txt', 'w', encoding='utf-8') as f:
                    f.write(self._generate_text_report())
                    
                print("\n" + "=" * 80)
                print("PROCESSAMENTO CONCLUÍDO")
                print("=" * 80)
                print(f"Estado Final: {self.current_state.value}")
                print(f"Challenge: {self.current_challenge.challenge_id if self.current_challenge else 'N/A'}")
                print(f"PoW Resolvido: {'SIM' if self.pow_solver.solution else 'NÃO'}")
                if self.pow_solver.solution:
                    print(f"  Nonce: {self.pow_solver.solution.get('nonce')}")
                    print(f"  Hash: {self.pow_solver.solution.get('hash')[:20]}...")
                print(f"Arquivos gerados:")
                print(f"  - filecrypt_flow_analysis.json")
                print(f"  - filecrypt_flow_analysis.txt")
                
                await browser.close()
                
        return self.final_result
        
    async def _collect_worker_messages(self, page: Page):
        """Coleta mensagens do Worker instrumentado"""
        try:
            messages = await page.evaluate('() => window._workerMessages || []')
            
            for msg in messages:
                worker_msg = WorkerMessage(
                    timestamp=msg.get('timestamp', datetime.now().isoformat()),
                    direction=msg.get('direction', 'unknown'),
                    worker_url=msg.get('workerUrl'),
                    content=msg.get('data'),
                    correlation_id=msg.get('correlationId'),
                    size=len(json.dumps(msg.get('data'))) if msg.get('data') else 0
                )
                self.worker_messages.append(worker_msg)
                
        except Exception as e:
            self._log_error("collect_worker_messages", e)


def main():
    """Ponto de entrada principal"""
    parser = argparse.ArgumentParser(description='FileCrypt Reverse Engineering Tool - Active Processor')
    parser.add_argument('url', help='URL do container FileCrypt para processar')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout em segundos (padrão: 300)')
    
    args = parser.parse_args()
    
    processor = FileCryptProcessor()
    
    try:
        asyncio.run(processor.run_processing(args.url))
    except KeyboardInterrupt:
        print("\nProcessamento interrompido pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\nErro fatal: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()