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
        city = es_client.get(index="cities", id=city_id)
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

        # Adiciona a query_string apenas se q não estiver vazio
        if request.q and request.q.strip():
            must_conditions.append({
                "query_string": {
                    "query": request.q,
                    "fields": [
                        "name^5",
                        "city^4",
                        "state^4",
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

        # Query final
        query = {
            "query": {
                "bool": {
                    "must": must_conditions
                }
            }
        }

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