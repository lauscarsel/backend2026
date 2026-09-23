"""
Dependencias de AUTORIZACIÓN — el corazón de la entrega del módulo 06.

Acá viven las 3 dependencias reutilizables que protegen TODOS los endpoints:

  1. get_current_user  → AUTENTICACIÓN (ya lo resolviste en el módulo 04,
                         acá está resuelto como referencia: 401 si no hay
                         token válido). ADEMÁS guarda el payload del token en
                         `request.state` para que require_scope lo lea.

  2. require_role      → AUTORIZACIÓN por rol. 403 si el rol no alcanza.
      ─────────────────────────────────────────────────────────────────────
      🔴 ESTADO ACTUAL: VULNERABLE. Devuelve al usuario sin verificar nada:
      cualquier autenticado "pasa" como si tuviera el rol pedido.
      💡 TU TRABAJO: comparar `current_user.role` contra `required` y
         responder 403 si no coinciden. El 403 (Forbidden) es el código
         de la AUTORIZACIÓN: autenticado pero sin permiso.
      ─────────────────────────────────────────────────────────────────────

  3. require_scope     → AUTORIZACIÓN por scope del TOKEN. 403 si el scope
                         del token no alcanza para la operación.
      ─────────────────────────────────────────────────────────────────────
      🔴 ESTADO ACTUAL: VULNERABLE. Lee el payload pero no valida nada.
      💡 TU TRABAJO: leer `request.state.token_payload` (que dejó
         get_current_user) y responder 403 si el scope pedido NO está
         dentro del scope del token.
      🧠 LECCIÓN (Pilar 3): el ROL es del usuario (lo relees de storage en
         cada request → el cambio de rol es inmediato). El SCOPE es del
         TOKEN (vive en el claim `scope`, lo fijó el login). Por eso
         require_scope lee del token y require_role del usuario.
      ─────────────────────────────────────────────────────────────────────
"""

from typing import Annotated, Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer
from jwt import InvalidTokenError

from app import security, storage
from app.models import Role, User

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: Annotated[dict | None, Depends(bearer_scheme)],
) -> User:
    """Quién sos: decodifica el JWT y carga el usuario desde storage."""

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciales inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise credentials_exception

    try:
        payload = security.decode_token(credentials.credentials)
        user_id = int(payload["sub"])
    except (InvalidTokenError, KeyError, ValueError):
        raise credentials_exception

    user = storage.get_user_by_id(user_id)

    if user is None:
        raise credentials_exception

    request.state.token_payload = payload

    return user


def require_role(required: Role) -> Callable:
    """Exige que el usuario tenga el rol requerido."""

    def checker(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:

        if current_user.role != required:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No tenés el rol necesario para esta operación",
            )

        return current_user

    return checker


def require_scope(required: str) -> Callable:
    """Exige que el TOKEN tenga el scope requerido."""

    def checker(
        request: Request,
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:

        payload = request.state.token_payload
        token_scope = payload.get("scope", "")

        if required not in token_scope.split():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="El token no tiene el scope necesario para esta operación",
            )

        return current_user

    return checker