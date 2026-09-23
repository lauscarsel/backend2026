"""
Controller de USUARIOS — gestión de usuarios y roles (solo admin).

┌─────────────────────────────────────────────────────────────────────────┐
│ 🔓 COMPLETÁS VOS: este archivo está VULNERABLE a propósito.            │
│                                                                         │
│   GET   /api/users            → lista usuarios de TU empresa            │
│   GET   /api/users/{id}       → detalle de un usuario                   │
│   PATCH /api/users/{id}/role  → cambia el rol de un usuario             │
│                                                                         │
│ La MATRIZ de la spec dice que estas 3 operaciones son de ADMIN          │
│ (los otros roles deben recibir 403) y que un admin SOLO opera          │
│ dentro de SU empresa (tenancy: nunca un user de Globex desde Acme).    │
│                                                                         │
│ ⚠️ Fijate que cada endpoint recibe `current_user` distinto:             │
│    - El que ya viene con Depends(require_role(...))  → falta el         │
│      check de tenancy dentro del cuerpo.                                │
│    - El que viene con Depends(get_current_user)     → falta el          │
│      require_role(ADMIN) y el check de tenancy.                         │
│    No hay UNA sola forma: ejercitá ambas.                               │
└─────────────────────────────────────────────────────────────────────────┘
"""


from fastapi import APIRouter, Depends, HTTPException, status

from app import storage
from app.dependencies import require_role
from app.models import Role, RoleChange, User, UserRead

router = APIRouter(prefix="/api", tags=["2 · Usuarios (admin)"])


@router.get("/users", response_model=list[UserRead])
def list_users(
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    """Lista los usuarios de TU empresa."""
    return storage.list_users(tenant_id=current_user.tenant_id)


@router.get("/users/{user_id}", response_model=UserRead)
def get_user(
    user_id: int,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    """Detalle de un usuario. 404 si no existe; 403 si es de otra empresa."""

    user = storage.get_user_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    if user.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés acceder a usuarios de otra empresa",
        )

    return user


@router.patch("/users/{user_id}/role", response_model=UserRead)
def change_role(
    user_id: int,
    body: RoleChange,
    current_user: User = Depends(require_role(Role.ADMIN)),
):
    """Cambia el rol de un usuario de la misma empresa."""

    user = storage.get_user_by_id(user_id)

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    if user.tenant_id != current_user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No podés modificar usuarios de otra empresa",
        )

    updated = storage.set_user_role(user_id, body.role)

    return updated