# This file is part of Guardian.
#
# Guardian is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Guardian is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Guardian. If not, see <https://www.gnu.org/licenses/>.

import json
import asyncio
import logging
from typing import Dict, List
from fastapi import WebSocket, WebSocketDisconnect
from schema.user import User

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"

from schema.util import StatusMessage

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    This class manages the active websocket connections.
    """

    def __init__(self):
        self.connections: Dict[str, List[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user: User):
        """
        Connects a new websocket.
        """
        await websocket.accept()
        async with self.lock:
            user_id = str(user.id)
            if user_id not in self.connections:
                self.connections[user_id] = []
            self.connections[user_id].append(websocket)
            logger.debug(f"Connected user {user_id}")

    async def disconnect(self, websocket: WebSocket, user: User):
        """
        Disconnects a websocket.
        """
        user_id = str(user.id)
        async with self.lock:
            if user_id in self.connections:
                self.connections[user_id].remove(websocket)
                if not self.connections[user_id]:
                    del self.connections[user_id]
                logger.debug(f"Disconnected user {user_id}")

    async def send(self, status: StatusMessage, user: User):
        """
        Sends a personal message to a user.
        """
        user_id = str(user.id)
        connections = self.connections.get(user_id, [])
        for websocket in connections:
            try:
                msg = json.loads(status.json())
                await websocket.send_json(msg)
            except WebSocketDisconnect as ex:
                logger.debug(f"WebSocketManager.send throw an WebSocketDisconnect exception: {ex}")
                logger.exception(ex)
                await self.disconnect(websocket, user)

    async def broadcast_json(self, message: str):
        """
        Broadcasts a message to all connected users.
        """
        async with self.lock:
            for user_id in self.connections:
                for websocket in self.connections[user_id]:
                    try:
                        await websocket.send_json(message)
                    except WebSocketDisconnect as ex:
                        logger.debug(f"WebSocketManager.broadcast_json throw an WebSocketDisconnect exception: {ex}")
                        logger.exception(ex)
                        await self.disconnect(websocket, User(id=user_id))


manager = WebSocketManager()
