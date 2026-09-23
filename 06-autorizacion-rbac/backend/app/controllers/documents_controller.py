"""
Controller de DOCUMENTOS — el recurso protegido (object-level + scopes).

┌─────────────────────────────────────────────────────────────────────────┐
│ 🔓 COMPLETÁS VOS: ESTE es el archivo más importante de la entrega.     │
│                                                                         │
│   POST   /api/documents            → crear     (scope "write")          │
│   GET    /api/documents            → listar    (públicos + los tuyos)   │
│   GET    /api/documents/{id}       → ver       (dueño / admin / público)│
│   PATCH  /api/documents/{id}       → editar    (dueño o admin, "write") │
│   DELETE /api/documents/{id}       → borrar    (admin, "write")         │
│   POST   /api/documents/{id}/publish → publicar (dueño o admin, "write")│
│                                                                         │
│ 🔴 El estado actual es el ATACANTE A01 del OWASP: **IDOR**.             │
│    Cualquier autenticado que conozca el id lee/edita/borra TODO.        │
│    Probalo: logueate como viewer@acme.com y pedí GET /api/documents/5   │
│    (el plan secreto de Globex) → responde 200. LUSTRADA.                │
│                                                                         │
│ ✅ TU TRABAJO, en cada endpoint:                                        │
│    1. SCOPE: los que modifican datos exigen Depends(require_scope("write"))│
│    2. TENANCY: si document.tenant_id != current_user.tenant_id → 403   │
│       (aplica SIEMPRE, incluso para documentos públicos)               │
│    3. OBJECT-LEVEL: si es privado → solo dueño (owner_id == tu id) o    │
│       admin del tenant. Si no → 403.                                   │
│    4. ROL: DELETE exige admin (matriz) — el resto de los GRISES salen  │
│       del scope: viewer tiene scope "read" → ya no llega a crear.      │
│                                                                         │
│ 🧠 Pregunta para la defensa: ¿por qué acá el 403 va DESPUÉS del 404?   │
│    (si un id no existe, no hay nada que proteger — pero en producción  │
│    algunos devuelven 404 también en cross-tenant para no filtrar       │
│    existencia. Acá usamos 403 para que la lección sea VISIBLE).        │
└─────────────────────────────────────────────────────────────────────────┘
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app import storage
from app.dependencies import get_current_user, require_role, require_scope
from app.models import DocumentCreate, DocumentRead, DocumentUpdate, Role, User

router = APIRouter(prefix="/api", tags=["3 · Documentos"])


@router.post(
    "/documents",
    response_model=DocumentRead,
    status_code=status.HTTP_201_CREATED,
)
def create_document(
    body: DocumentCreate,
    current_user: User = Depends(require_scope("write")),
):
    """Crea un documento privado y perteneciente al usuario actual."""

    return storage.create_document(owner=current_user, body=body)


@router.get("/documents", response_model=list[DocumentRead])
def list_documents(
    current_user: User = Depends(get_current_user),
):
    """Lista documentos públicos de la empresa y documentos propios."""

    return storage.list_documents(
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
    )


@router.get("/documents/{doc_id}", response_model=DocumentRead)
def get_document(
    doc_id: int,
    current_user: User = Depends(get_current_user),
):
    """Obtiene un documento respetando tenancy y permisos de objeto."""

    doc = storage.get_document(doc_id)

    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documento no encontrado",
        )

    # Primero tenancy: nadie puede acceder a documentos de otra empresa.
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés acceder a documentos de otra empresa",
        )

    # Los documentos públicos los puede ver cualquier usuario
    # de la misma empresa.
    if doc.visibility == "public":
        return doc

    # Los documentos privados los puede ver el dueño o un admin.
    if doc.owner_id == current_user.id or current_user.role == Role.ADMIN:
        return doc

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="No podés acceder a este documento",
    )


@router.patch("/documents/{doc_id}", response_model=DocumentRead)
def update_document(
    doc_id: int,
    body: DocumentUpdate,
    current_user: User = Depends(require_scope("write")),
):
    """Edita un documento: solo el dueño o un admin de la misma empresa."""

    doc = storage.get_document(doc_id)

    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documento no encontrado",
        )

    # Tenancy.
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés editar documentos de otra empresa",
        )

    # Object-level authorization.
    if doc.owner_id != current_user.id and current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés editar este documento",
        )

    return storage.update_document(doc_id, body)


@router.delete("/documents/{doc_id}", response_model=DocumentRead)
def delete_document(
    doc_id: int,
    current_user: User = Depends(require_role(Role.ADMIN)),
    _scope_user: User = Depends(require_scope("write")),
):
    """Borra un documento: solo admin con scope write y de su empresa."""

    doc = storage.get_document(doc_id)

    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documento no encontrado",
        )

    # Tenancy: incluso un admin no puede borrar documentos
    # de otra empresa.
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés borrar documentos de otra empresa",
        )

    return storage.delete_document(doc_id)


@router.post("/documents/{doc_id}/publish", response_model=DocumentRead)
def publish_document(
    doc_id: int,
    current_user: User = Depends(require_scope("write")),
):
    """Publica un documento: dueño o admin de la misma empresa."""

    doc = storage.get_document(doc_id)

    if doc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Documento no encontrado",
        )

    # Tenancy.
    if doc.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés publicar documentos de otra empresa",
        )

    # Solo dueño o admin.
    if doc.owner_id != current_user.id and current_user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés publicar este documento",
        )

    return storage.set_document_published(doc_id, True)