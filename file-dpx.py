#!/usr/bin/env python3
"""
FileCrypt Bypass - Puro Python (no sandbox, no rendering)
Resolve PoW via HTTP requests e extrai link final do MediaFire/1File
"""

import requests
import hashlib
import re
import json
import time
import logging
from typing import Optional, Dict, Any, Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class PoWChallenge:
    """Representa um desafio PoW detectado"""
    pow_id: str
    algorithm: str  # 'sha256', 'scrypt', etc
    difficulty: int  # número de zeros necessários no início do hash
    prefix: Optional[str] = None
    suffix: Optional[str] = None
    extra_params: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.extra_params is None:
            self.extra_params = {}


@dataclass
class BypassResult:
    """Resultado do bypass"""
    success: bool
    final_url: Optional[str] = None
    error_message: Optional[str] = None
    response_data: Optional[Dict] = None
    cookies: Optional[Dict] = None
    evidence_log: list = None
    
    def __post_init__(self):
        if self.evidence_log is None:
            self.evidence_log = []


class FileCryptBypass:
    """
    Bypass do FileCrypt via HTTP puro - sem browser, sem JavaScript
    """
    
    def __init__(self, session: Optional[requests.Session] = None):
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
        })
        self.evidence_log = []
        
    def _log_evidence(self, stage: str, data: Dict):
        """Registra evidência observável"""
        entry = {
            'timestamp': time.time(),
            'stage': stage,
            'data': data
        }
        self.evidence_log.append(entry)
        logger.debug(f"[EVIDENCE] {stage}: {json.dumps(data, indent=2)[:200]}...")
        
    def _extract_pow_params(self, html: str, url: str) -> Optional[PoWChallenge]:
        """
        Extrai parâmetros PoW do HTML - evidence-based, não assume formato
        """
        self._log_evidence('html_raw', {'length': len(html), 'url': url})
        
        # Padrões comuns de campos PoW
        patterns = {
            'pow_id': r'(?:name|id)=["\']pow_id["\'][^>]*value=["\']([^"\']+)',
            'pow_nonce': r'(?:name|id)=["\']pow_nonce["\'][^>]*value=["\']([^"\']*)',
            'pow_difficulty': r'(?:name|id)=["\']pow_difficulty["\'][^>]*value=["\'](\d+)',
            'pow_algorithm': r'(?:name|id)=["\']pow_algorithm["\'][^>]*value=["\']([^"\']+)',
            'pow_prefix': r'(?:name|id)=["\']pow_prefix["\'][^>]*value=["\']([^"\']*)',
            'pow_suffix': r'(?:name|id)=["\']pow_suffix["\'][^>]*value=["\']([^"\']*)',
        }
        
        extracted = {}
        for field, pattern in patterns.items():
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                extracted[field] = matches[0]
                logger.info(f"[EXTRACTED] {field}: {matches[0][:50]}...")
                
        self._log_evidence('extracted_fields', extracted)
        
        if not extracted.get('pow_id'):
            # Tenta padrões alternativos (JavaScript inline)
            js_patterns = [
                r'pow_id\s*[=:]\s*["\']([^"\']+)',
                r'["\']pow_id["\']\s*[=:]\s*["\']([^"\']+)',
                r'var\s+pow_id\s*=\s*["\']([^"\']+)',
            ]
            for pattern in js_patterns:
                match = re.search(pattern, html)
                if match:
                    extracted['pow_id'] = match.group(1)
                    logger.info(f"[EXTRACTED-JS] pow_id: {extracted['pow_id']}")
                    break
                    
        if not extracted.get('pow_id'):
            self._log_evidence('error', {'message': 'pow_id não encontrado'})
            return None
            
        # Detecta algoritmo (default: sha256)
        algorithm = extracted.get('pow_algorithm', 'sha256').lower()
        
        # Detecta dificuldade (default: 4 zeros)
        difficulty = int(extracted.get('pow_difficulty', 4))
        
        challenge = PoWChallenge(
            pow_id=extracted['pow_id'],
            algorithm=algorithm,
            difficulty=difficulty,
            prefix=extracted.get('pow_prefix', ''),
            suffix=extracted.get('pow_suffix', ''),
            extra_params=extracted
        )
        
        self._log_evidence('challenge_created', {
            'pow_id': challenge.pow_id,
            'algorithm': challenge.algorithm,
            'difficulty': challenge.difficulty
        })
        
        return challenge
        
    def _solve_sha256(self, challenge: PoWChallenge) -> Optional[str]:
        """
        Resolve desafio SHA-256 - busca nonce que produz hash com N zeros iniciais
        """
        if challenge.algorithm != 'sha256':
            return None
            
        target_prefix = '0' * challenge.difficulty
        nonce = 0
        start_time = time.time()
        
        logger.info(f"[SOLVER] Iniciando busca por nonce (dificuldade: {challenge.difficulty})...")
        
        while True:
            # Constrói string para hash
            data = f"{challenge.prefix}{nonce}{challenge.suffix}{challenge.pow_id}"
            
            # Calcula SHA-256
            hash_result = hashlib.sha256(data.encode()).hexdigest()
            
            # Verifica se satisfaz dificuldade
            if hash_result.startswith(target_prefix):
                elapsed = time.time() - start_time
                logger.info(f"[SOLVER] Nonce encontrado: {nonce} (tempo: {elapsed:.2f}s)")
                logger.info(f"[SOLVER] Hash: {hash_result}")
                
                self._log_evidence('pow_solved', {
                    'nonce': nonce,
                    'hash': hash_result,
                    'elapsed': elapsed,
                    'iterations': nonce
                })
                
                return str(nonce)
                
            nonce += 1
            
            # Log progresso a cada 100k iterações
            if nonce % 100000 == 0:
                logger.debug(f"[SOLVER] Testados {nonce} nonces...")
                
            # Timeout de segurança (30 segundos)
            if time.time() - start_time > 30:
                logger.error("[SOLVER] Timeout - não encontrou nonce em 30s")
                return None
                
    def _solve_pow(self, challenge: PoWChallenge) -> Optional[str]:
        """
        Dispatcher de solvers baseado no algoritmo detectado
        """
        solvers = {
            'sha256': self._solve_sha256,
            # Adicionar mais algoritmos conforme detectados
        }
        
        solver = solvers.get(challenge.algorithm)
        if not solver:
            logger.error(f"[SOLVER] Algoritmo não suportado: {challenge.algorithm}")
            return None
            
        return solver(challenge)
        
    def _find_verification_endpoint(self, html: str, base_url: str) -> Optional[str]:
        """
        Descobre endpoint de verificação - evidence-based
        """
        # Padrões comuns de endpoints
        patterns = [
            r'action=["\']([^"\']*verify[^"\']*)',
            r'action=["\']([^"\']*check[^"\']*)',
            r'action=["\']([^"\']*pow[^"\']*)',
            r'url\s*[=:]\s*["\']([^"\']*verify[^"\']*)',
            r'fetch\(["\']([^"\']*verify[^"\']*)',
            r'post\(["\']([^"\']*verify[^"\']*)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                self._log_evidence('endpoint_found', {'pattern': pattern, 'url': full_url})
                return full_url
                
        # Fallback: tenta endpoints comuns
        common_endpoints = ['/verify', '/check', '/api/verify', '/api/check', '/pow/verify']
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for endpoint in common_endpoints:
            url = base + endpoint
            self._log_evidence('endpoint_fallback', {'url': url})
            return url
            
        return None
        
    def _submit_pow(self, challenge: PoWChallenge, nonce: str, endpoint: str) -> Optional[Dict]:
        """
        Submete solução PoW para o endpoint de verificação
        """
        payload = {
            'pow_id': challenge.pow_id,
            'pow_nonce': nonce,
            'pow_elapsed': str(int(time.time())),
            'pow_algorithm': challenge.algorithm,
        }
        
        # Adiciona campos extras detectados
        for key, value in challenge.extra_params.items():
            if key not in payload and not key.startswith('pow_'):
                payload[key] = value
                
        self._log_evidence('submit_payload', payload)
        
        try:
            response = self.session.post(endpoint, data=payload, timeout=30)
            self._log_evidence('submit_response', {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'url': response.url
            })
            
            # Tenta parsear como JSON
            try:
                data = response.json()
                self._log_evidence('response_json', data)
                return data
            except:
                # Retorna HTML/texto
                return {
                    'status_code': response.status_code,
                    'text': response.text[:1000],
                    'url': response.url
                }
                
        except Exception as e:
            self._log_evidence('submit_error', {'error': str(e)})
            return None
            
    def _extract_final_link(self, response_data: Dict, html: str) -> Optional[str]:
        """
        Extrai link final (MediaFire/1File) da resposta - evidence-based
        """
        sources = []
        
        if isinstance(response_data, dict):
            # Procura em campos comuns
            link_fields = ['download_url', 'url', 'link', 'redirect', 'location', 
                        'final_url', 'mediafire', '1file', 'direct_link']
            for field in link_fields:
                if field in response_data and isinstance(response_data[field], str):
                    if 'mediafire' in response_data[field] or '1file' in response_data[field]:
                        sources.append(('json_field', response_data[field]))
                        
            # Procura em redirect
            if 'redirect' in response_data:
                sources.append(('json_redirect', response_data['redirect']))
                
        # Procura no HTML
        if html:
            # Padrões de links diretos
            patterns = [
                r'href=["\'](https?://[^"\']*mediafire\.com[^"\']+)',
                r'href=["\'](https?://[^"\']*1file\.com[^"\']+)',
                r'href=["\'](https?://[^"\']*1fichier\.com[^"\']+)',
                r'url["\']?\s*[=:]\s*["\'](https?://[^"\']+(?:mediafire|1file|1fichier)[^"\']+)',
                r'data-url=["\'](https?://[^"\']+(?:mediafire|1file|1fichier)[^"\']+)',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    sources.append(('html_pattern', match))
                    
        self._log_evidence('extracted_links', {'count': len(sources), 'sources': sources[:5]})
        
        # Retorna primeiro link válido
        for source_type, link in sources:
            if link.startswith('http'):
                logger.info(f"[EXTRACTED] Link final ({source_type}): {link}")
                return link
                
        return None
        
    def bypass(self, filecrypt_url: str) -> BypassResult:
        """
        Executa bypass completo em um link do FileCrypt
        
        Args:
            filecrypt_url: URL completa do FileCrypt (ex: https://filecrypt.co/...)
            
        Returns:
            BypassResult com sucesso/fracasso e link final
        """
        logger.info(f"[BYPASS] Iniciando: {filecrypt_url}")
        
        # Etapa 1: Carrega página inicial
        try:
            response = self.session.get(filecrypt_url, timeout=30)
            html = response.text
            self._log_evidence('initial_load', {
                'status': response.status_code,
                'content_length': len(html),
                'url': response.url
            })
        except Exception as e:
            return BypassResult(
                success=False,
                error_message=f"Falha ao carregar página: {e}",
                evidence_log=self.evidence_log
            )
            
        # Etapa 2: Extrai parâmetros PoW
        challenge = self._extract_pow_params(html, response.url)
        if not challenge:
            # Pode ser que não tenha PoW ou já redirecionou
            final_link = self._extract_final_link({}, html)
            if final_link:
                return BypassResult(
                    success=True,
                    final_url=final_link,
                    evidence_log=self.evidence_log
                )
            return BypassResult(
                success=False,
                error_message="Não foi possível extrair parâmetros PoW",
                evidence_log=self.evidence_log
            )
            
        # Etapa 3: Resolve PoW
        nonce = self._solve_pow(challenge)
        if not nonce:
            return BypassResult(
                success=False,
                error_message="Falha ao resolver PoW",
                evidence_log=self.evidence_log
            )
            
        # Etapa 4: Encontra endpoint de verificação
        endpoint = self._find_verification_endpoint(html, response.url)
        if not endpoint:
            return BypassResult(
                success=False,
                error_message="Endpoint de verificação não encontrado",
                evidence_log=self.evidence_log
            )
            
        # Etapa 5: Submete solução
        verify_response = self._submit_pow(challenge, nonce, endpoint)
        if not verify_response:
            return BypassResult(
                success=False,
                error_message="Falha na submissão do PoW",
                evidence_log=self.evidence_log
            )
            
        # Etapa 6: Extrai link final
        final_link = self._extract_final_link(
            verify_response, 
            verify_response.get('text', '') if isinstance(verify_response, dict) else ''
        )
        
        if final_link:
            return BypassResult(
                success=True,
                final_url=final_link,
                response_data=verify_response,
                cookies=dict(self.session.cookies),
                evidence_log=self.evidence_log
            )
            
        return BypassResult(
            success=False,
            error_message="Link final não encontrado na resposta",
            response_data=verify_response,
            evidence_log=self.evidence_log
        )


# Exemplo de uso
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python filecrypt_bypass.py <url_filecrypt>")
        print("Exemplo: python filecrypt_bypass.py https://filecrypt.co/Container/ABC123.html")
        sys.exit(1)
        
    url = sys.argv[1]
    bypass = FileCryptBypass()
    result = bypass.bypass(url)
    
    print("\n" + "="*60)
    print("RESULTADO DO BYPASS")
    print("="*60)
    print(f"Sucesso: {result.success}")
    
    if result.success:
        print(f"Link Final: {result.final_url}")
        print(f"Cookies: {result.cookies}")
    else:
        print(f"Erro: {result.error_message}")
        
    print(f"\nEvidências registradas: {len(result.evidence_log)} entradas")
    
    # Salva evidências em arquivo para análise
    with open('bypass_evidence.json', 'w') as f:
        json.dump(result.evidence_log, f, indent=2, default=str)
    print("Evidências salvas em: bypass_evidence.json")