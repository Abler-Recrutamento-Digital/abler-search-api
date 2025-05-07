from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Security, Depends, status
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse
from elasticsearch import Elasticsearch
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import ssl
import certifi
import secrets

load_dotenv()

# Configurações de segurança do Swagger
SWAGGER_USERNAME = os.getenv("SWAGGER_USERNAME", "admin")
SWAGGER_PASSWORD = os.getenv("SWAGGER_PASSWORD", "Abler2024$@")

app = FastAPI(
    title="abler Search API",
    description="API para busca de candidatos no banco de talentos da abler",
    docs_url=None,
    redoc_url=None
)

# Configuração de segurança
API_KEY_HEADER = APIKeyHeader(name="X-API-Token", auto_error=True)
API_TOKEN = os.getenv("API_TOKEN")
security = HTTPBasic()

# Configuração do Elasticsearch
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "https://hulk-es-http.elasticsearch.svc.cluster.local:9200")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "candidates")
ELASTICSEARCH_INDEX_CITIES = os.getenv("ELASTICSEARCH_INDEX_CITIES", "cities")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD")

# Configuração do cliente Elasticsearch
es_config = {}

# Adiciona autenticação básica apenas se username e password estiverem presentes
if ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD:
    print(f"DEBUG - Configurando autenticação básica para Elasticsearch com usuário: {ELASTICSEARCH_USERNAME}")
    es_config["basic_auth"] = (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD)
else:
    print("ALERTA - ELASTICSEARCH_USERNAME ou ELASTICSEARCH_PASSWORD não estão configurados!")
    print("ELASTICSEARCH_USERNAME presente:", ELASTICSEARCH_USERNAME is not None)
    print("ELASTICSEARCH_PASSWORD presente:", ELASTICSEARCH_PASSWORD is not None)

# Adiciona configurações SSL apenas se a URL for HTTPS
if ELASTICSEARCH_URL.startswith("https://"):
    print(f"DEBUG - Configurando SSL para Elasticsearch URL: {ELASTICSEARCH_URL}")
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    es_config.update({
        "ssl_context": context,
        "verify_certs": False
    })

# Mostra a configuração final (sem expor a senha)
debug_config = es_config.copy()
if "basic_auth" in debug_config:
    auth = debug_config["basic_auth"]
    debug_config["basic_auth"] = (auth[0], "********") if auth[0] else ("None", "********")
print("DEBUG - Configuração Elasticsearch:", debug_config)

# Cliente Elasticsearch
try:
    es_client = Elasticsearch(ELASTICSEARCH_URL, **es_config)
    # Teste de conectividade
    info = es_client.info()
    print(f"DEBUG - Conexão com Elasticsearch estabelecida. Versão: {info.get('version', {}).get('number')}")
except Exception as e:
    print(f"ERRO - Falha ao conectar com Elasticsearch: {str(e)}")

async def get_city_data(city_id: int) -> Dict[str, str]:
    try:
        city = es_client.get(index=ELASTICSEARCH_INDEX_CITIES, id=city_id)
        return {
            "city": city["_source"]["name"],
            "state": city["_source"]["state"]["name"]
        }
    except:
        return {"city": None, "state": None}

class SearchRequest(BaseModel):
    q: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin_identifier: Optional[str] = None

class CityRequest(BaseModel):
    q: str
    exact: Optional[bool] = False
    size: Optional[int] = 20

class CityResponse(BaseModel):
    total: int
    query: Dict[str, Any]
    results: List[Dict[str, Any]]

class SearchResponse(BaseModel):
    total: int
    results: List[Dict[str, Any]]

class Education(BaseModel):
    course: str
    degree: Optional[str] = None
    institution: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    present: bool = False

class Experience(BaseModel):
    company: str
    title: str
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    description: str
    salary: Optional[float] = None
    present: bool = False

class Course(BaseModel):
    course_name: str
    institution: str
    end_date: Optional[str] = None
    duration: Optional[str] = None

class Language(BaseModel):
    language: str
    level: Optional[str] = None

class CandidateResponse(BaseModel):
    abler_id: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    birthday: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    neighborhood: Optional[str] = None
    profile_url: str
    linkedin_public_identifier: Optional[str] = None
    salary_minimum: Optional[float] = None
    salary_maximum: Optional[float] = None
    education: List[Education] = []
    experience: List[Experience] = []
    courses: List[Course] = []
    languages: List[Language] = []

def verify_swagger_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    is_username_correct = secrets.compare_digest(credentials.username.encode("utf8"), SWAGGER_USERNAME.encode("utf8"))
    is_password_correct = secrets.compare_digest(credentials.password.encode("utf8"), SWAGGER_PASSWORD.encode("utf8"))
    
    if not (is_username_correct and is_password_correct):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    if api_key != API_TOKEN:
        raise HTTPException(
            status_code=403,
            detail="Could not validate API token"
        )
    return api_key

# Rota raiz redirecionando para o Swagger
@app.get("/", include_in_schema=False)
async def root():
    return RedirectResponse(url="/docs")

# Rota do Swagger protegida
@app.get("/docs", include_in_schema=False)
async def get_swagger_documentation(credentials: HTTPBasicCredentials = Depends(verify_swagger_credentials)):
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Abler Search API - Swagger UI")

# Rota do OpenAPI JSON protegida
@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_json(credentials: HTTPBasicCredentials = Depends(verify_swagger_credentials)):
    from fastapi.openapi.utils import get_openapi
    openapi_schema = get_openapi(
        title="abler Search API",
        version="1.0.0",
        description="API para busca de candidatos no banco de talentos da abler",
        routes=app.routes
    )
    return openapi_schema

@app.post("/search_abler", response_model=SearchResponse)
async def search_candidates(
    request: SearchRequest,
    api_key: str = Depends(verify_api_key)
) -> SearchResponse:
    try:
        # Construindo a query base com query_string
        must_conditions = []
        
        # Variável para armazenar IDs de cidades encontradas
        city_ids = []

        # Adiciona a query_string apenas se q não estiver vazio
        if request.q and request.q.strip():
            query_text = request.q.strip()
            
            # Primeiro, vamos verificar se a consulta contém operadores OR entre nomes de cidades
            possible_city_queries = []
            
            # Verifica se há operadores OR explícitos
            if " OR " in query_text:
                or_terms = [term.strip() for term in query_text.split(" OR ")]
                for term in or_terms:
                    if term and len(term) > 2:  # Ignorar termos muito curtos
                        # Para termos que parecem ser compostos (como "São José dos Pinhais")
                        possible_city_queries.append(term)
            
            # Também verifica os termos individuais
            individual_terms = [term.strip('()"\'"') for term in query_text.replace(" AND ", " ").replace(" OR ", " ").split()]
            for term in individual_terms:
                if term and len(term) > 2 and term not in possible_city_queries:  # Ignorar termos muito curtos e duplicados
                    possible_city_queries.append(term)
            
            print(f"DEBUG - Possíveis consultas de cidades: {possible_city_queries}")
            
            # Buscar cidades para cada possível nome
            try:
                for city_query in possible_city_queries:
                    # Para termos que parecem nomes de cidades, vamos buscar com prioridade para match_phrase
                    cities_query = {
                        "query": {
                            "bool": {
                                "should": [
                                    {"match_phrase": {"name": {"query": city_query, "boost": 10}}},
                                    {"match": {"name": {"query": city_query, "fuzziness": "AUTO"}}}
                                ],
                                "minimum_should_match": 1
                            }
                        },
                        "size": 5  # Limitando a 5 resultados por termo
                    }
                    
                    cities_response = es_client.search(
                        index=ELASTICSEARCH_INDEX_CITIES,
                        body=cities_query
                    )
                    
                    # Extrair IDs das cidades encontradas
                    for city_hit in cities_response["hits"]["hits"]:
                        city_id = city_hit["_id"]
                        if city_id not in city_ids:  # Evitar duplicatas
                            city_score = city_hit.get("_score", 0)
                            # Só adiciona a cidade se o score for bom (maior que 5)
                            if city_score > 5:
                                city_ids.append(city_id)
                                print(f"DEBUG - Cidade encontrada: {city_hit['_source'].get('name')} (ID: {city_id}, Score: {city_score})")
                
                print(f"DEBUG - Total de cidades encontradas: {len(city_ids)} IDs")
            except Exception as city_error:
                print(f"ALERTA - Erro ao buscar cidades: {str(city_error)}")
                # Continua mesmo se houver erro na busca de cidades
            
            # Adiciona a consulta principal para o índice de candidatos
            must_conditions.append({
                "query_string": {
                    "query": query_text,
                    "fields": [
                        "name^5",
                        "cover_letter_text^4",
                        "national_experiences.role_name^4",
                        "national_experiences.activities_text^3",
                        "national_experiences.company^2",
                        "international_experiences.role_name^4",
                        "international_experiences.activities_text^3",
                        "international_experiences.company^2",
                        "educational_profiles.course_text^2",
                        "complementary_trainings.course^4",
                        "complementary_trainings.institution",
                        "*"
                    ],
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                    "allow_leading_wildcard": True,
                    "fuzzy_max_expansions": 50,
                    "fuzziness": "AUTO"
                }
            })

        # Adiciona condições para campos opcionais se fornecidos e não vazios
        if request.email and request.email.strip():
            must_conditions.append({"term": {"email.keyword": request.email.strip()}})
        if request.phone and request.phone.strip():
            must_conditions.append({"term": {"phone.keyword": request.phone.strip()}})
        if request.linkedin_identifier and request.linkedin_identifier.strip():
            must_conditions.append({"term": {"linkedin_identifier.keyword": request.linkedin_identifier.strip()}})

        # Se não houver nenhuma condição, retorna lista vazia
        if not must_conditions:
            return SearchResponse(total=0, results=[])

        # Estrutura base da query
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            }
        }

        # Se encontramos cidades, adicionar um "should" para aumentar o score de candidatos nessas cidades
        if city_ids:
            query["query"]["bool"]["should"] = [
                {"terms": {"address.city_id": city_ids, "boost": 10.0}}
            ]
            # Define minimum_should_match como 0 para que seja um boost, não um requisito
            query["query"]["bool"]["minimum_should_match"] = 0

        print("="*50)
        print("DEBUG - Elasticsearch Query:")
        print(query)
        print("="*50)

        # Fazendo a busca no Elasticsearch
        try:
            response = es_client.search(
                index=ELASTICSEARCH_INDEX,
                body=query,
                size=50  # Limitando a 50 resultados por página
            )
            
            print("="*50)
            print("DEBUG - Elasticsearch Response:")
            print(f"Total hits: {response.get('hits', {}).get('total', {}).get('value', 0)}")
            print("="*50)
        except Exception as es_error:
            print(f"ERRO - Falha na consulta ao Elasticsearch: {str(es_error)}")
            raise HTTPException(
                status_code=500,
                detail=f"Error searching in Elasticsearch: {str(es_error)}"
            )

        # Processando os resultados
        hits = response["hits"]["hits"]
        candidates = []
        
        for hit in hits:
            source = hit["_source"]
            
            # Busca dados da cidade e estado
            address = source.get("address", {})
            city_id = address.get("city_id")
            city_data = await get_city_data(city_id) if city_id else {"city": None, "state": None}
            
            # Formatando o candidato conforme o novo padrão
            candidate = {
                "abler_id": str(source.get("id", "")),
                "created_at": source.get("created_at"),
                "updated_at": source.get("profile_updated_at"),
                "name": source.get("name"),
                "email": source.get("email"),
                "phone": source.get("phone", "").replace("(", "").replace(")", "").replace("-", "").strip(),
                "birthday": source.get("birthday"),
                "city": city_data["city"],
                "state": city_data["state"],
                "country": source.get("nationality"),
                "neighborhood": address.get("neighborhood"),
                "profile_url": f"https://ats.abler.com.br/app/candidates/{source.get('id', '')}",
                "linkedin_public_identifier": source.get("linkedin_identifier"),
                "salary_minimum": float(source.get("salary_intended", 0)) if source.get("salary_intended") else None,
                "salary_maximum": float(source.get("salary_intended_max_parsed", 0)) if source.get("salary_intended_max_parsed") else None,
                "education": [
                    {
                        "course": edu.get("course_text", ""),
                        "degree": edu.get("level"),
                        "institution": None,
                        "start_date": None,
                        "end_date": None,
                        "present": False
                    } for edu in source.get("educational_profiles", []) if edu.get("course_text")
                ],
                "experience": [
                    {
                        "company": exp.get("company", ""),
                        "title": exp.get("role_name", ""),
                        "start_date": None,
                        "end_date": None,
                        "description": exp.get("activities_text", ""),
                        "salary": float(exp.get("last_salary", 0)) if exp.get("last_salary") else None,
                        "present": False
                    } for exp in source.get("national_experiences", []) + source.get("international_experiences", [])
                ],
                "courses": [
                    {
                        "course_name": course.get("course", ""),
                        "institution": course.get("institution", ""),
                        "end_date": None,
                        "duration": "Curta (até 40 horas)"
                    } for course in source.get("complementary_trainings", [])
                ],
                "languages": [
                    {
                        "language": "Português" if lang.get("language_id") == 2 else "Inglês" if lang.get("language_id") == 1 else "Outro",
                        "level": lang.get("level")
                    } for lang in source.get("candidates_languages", [])
                ]
            }
            
            candidates.append(candidate)

        return SearchResponse(
            total=response["hits"]["total"]["value"],
            results=candidates
        )

    except Exception as e:
        print(f"ERRO GERAL na busca: {str(e)}") # Adicionando log de erro geral
        raise HTTPException(
            status_code=500,
            detail=f"Error searching huntings: {str(e)}"
        )

@app.post("/cities", response_model=CityResponse)
async def search_cities(
    request: CityRequest,
    api_key: str = Depends(verify_api_key)
) -> CityResponse:
    """
    Busca cidades no índice do Elasticsearch.
    
    Este endpoint é útil para entender a estrutura do índice 'cities' e
    como os dados são armazenados e podem ser consultados.
    
    Se o parâmetro 'q' estiver vazio, retorna todas as cidades (limitado a 10.000 resultados).
    """
    try:
        # Definir um tamanho máximo seguro para a consulta
        max_size = 10000
        size = min(request.size, max_size)
        
        # Se q estiver vazio, buscar todas as cidades
        if not request.q.strip():
            print(f"DEBUG - Listando todas as cidades (limitado a {size} resultados)")
            
            # Consulta para retornar todas as cidades sem ordenação
            # Removida a ordenação por name.keyword que estava causando o erro
            query = {
                "query": {
                    "match_all": {}
                }
                # Ordenação removida pois o campo name.keyword não existe no mapeamento
            }
            
            # Log da consulta
            print("="*50)
            print("DEBUG - Consultando todas as cidades")
            print(query)
            print("="*50)
            
            try:
                # Executando a consulta
                response = es_client.search(
                    index=ELASTICSEARCH_INDEX_CITIES,
                    body=query,
                    size=size
                )
                
                # Processando resultados
                hits = response["hits"]["hits"]
                cities = []
                
                for hit in hits:
                    city_data = hit["_source"]
                    city_info = {
                        "id": hit["_id"],
                        "name": city_data.get("name"),
                        "state": city_data.get("state", {}).get("name"),
                        "state_id": city_data.get("state", {}).get("id"),
                        "score": hit.get("_score")
                    }
                    cities.append(city_info)
                
                print(f"DEBUG - Total de cidades retornadas: {len(cities)}")
                print("="*50)
                
                return CityResponse(
                    total=response["hits"]["total"]["value"],
                    query=query,
                    results=cities
                )
            except Exception as search_error:
                print(f"ERRO - Falha na busca de todas as cidades: {str(search_error)}")
                # Verifica se há informações sobre o mapeamento para ajudar no diagnóstico
                try:
                    mapping = es_client.indices.get_mapping(index=ELASTICSEARCH_INDEX_CITIES)
                    print(f"DEBUG - Mapeamento do índice: {mapping}")
                except Exception as mapping_error:
                    print(f"ERRO - Não foi possível obter o mapeamento do índice: {str(mapping_error)}")
                
                raise HTTPException(
                    status_code=500,
                    detail=f"Erro ao buscar todas as cidades: {str(search_error)}"
                )
        
        # Se a consulta contiver operador OR, separamos e tratamos cada termo individualmente
        if " OR " in request.q:
            city_names = [term.strip() for term in request.q.split(" OR ")]
            print(f"DEBUG - Buscando cidades separadamente: {city_names}")
            
            # Lista de consultas para cada cidade
            should_clauses = []
            
            for city_name in city_names:
                if request.exact:
                    # Busca exata para cada cidade - usando match_phrase em vez de term com .keyword
                    should_clauses.append({"match_phrase": {"name": {"query": city_name, "boost": 15}}})
                else:
                    # Busca por frase para cada cidade
                    should_clauses.append({"match_phrase": {"name": {"query": city_name, "boost": 10}}})
                    # Adicionamos também uma correspondência menos estrita como fallback
                    should_clauses.append({"match": {"name": {"query": city_name, "fuzziness": "AUTO"}}})
            
            # Construindo a query com operadores OR (should)
            query = {
                "query": {
                    "bool": {
                        "should": should_clauses,
                        "minimum_should_match": 1
                    }
                }
            }
        else:
            # Para consultas sem OR, mantemos o comportamento original
            if request.exact:
                # Busca exata pelo nome da cidade - usando match_phrase em vez de term com .keyword
                query = {
                    "query": {
                        "bool": {
                            "should": [
                                {"match_phrase": {"name": {"query": request.q.strip(), "slop": 0, "boost": 15}}},
                                {"match": {"name": {"query": request.q.strip(), "operator": "AND"}}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                }
            else:
                # Busca usando match para nomes de cidades
                query = {
                    "query": {
                        "bool": {
                            "should": [
                                {"match_phrase": {"name": {"query": request.q.strip(), "boost": 10}}},
                                {"match": {"name": {"query": request.q.strip(), "fuzziness": "AUTO"}}},
                                {"match": {"state.name": {"query": request.q.strip(), "boost": 2}}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                }
        
        # Log da consulta
        print("="*50)
        print("DEBUG - Consulta de Cidades:")
        print(query)
        print("="*50)
        
        # Executando a consulta
        response = es_client.search(
            index=ELASTICSEARCH_INDEX_CITIES,
            body=query,
            size=min(request.size, max_size)  # Limitando ao tamanho máximo seguro
        )
        
        # Processando resultados
        hits = response["hits"]["hits"]
        cities = []
        
        for hit in hits:
            city_data = hit["_source"]
            city_info = {
                "id": hit["_id"],
                "name": city_data.get("name"),
                "state": city_data.get("state", {}).get("name"),
                "state_id": city_data.get("state", {}).get("id"),
                "score": hit.get("_score")
            }
            cities.append(city_info)
        
        print(f"DEBUG - Cidades encontradas: {len(cities)}")
        print("="*50)
        
        return CityResponse(
            total=response["hits"]["total"]["value"],
            query=query,
            results=cities
        )
            
    except Exception as e:
        print(f"ERRO - Falha na busca de cidades: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao buscar cidades: {str(e)}"
        )