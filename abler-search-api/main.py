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
ELASTICSEARCH_URL = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "candidates")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD")

# Configuração do cliente Elasticsearch
es_config = {
    "basic_auth": (ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD)
}

# Adiciona configurações SSL apenas se a URL for HTTPS
if ELASTICSEARCH_URL.startswith("https://"):
    context = ssl.create_default_context(cafile=certifi.where())
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    es_config.update({
        "ssl_context": context,
        "verify_certs": False
    })

# Cliente Elasticsearch
es_client = Elasticsearch(ELASTICSEARCH_URL, **es_config)

class SearchRequest(BaseModel):
    q: str
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin_identifier: Optional[str] = None

class SearchResponse(BaseModel):
    huntings: List[Dict[str, Any]]
    total: int

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
            return SearchResponse(huntings=[], total=0)

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
        response = es_client.search(
            index=ELASTICSEARCH_INDEX,
            body=query,
            size=50  # Limitando a 50 resultados por página
        )

        print("="*50)
        print("DEBUG - Elasticsearch Response:")
        print(response)
        print("="*50)

        # Processando os resultados
        hits = response["hits"]["hits"]
        candidates = [hit["_source"] for hit in hits]
        total = response["hits"]["total"]["value"]

        return SearchResponse(
            huntings=candidates,
            total=total
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error searching huntings: {str(e)}"
        )