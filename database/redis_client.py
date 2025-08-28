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
import time
import logging
from redis.exceptions import ConnectionError
from typing import Dict, Callable, Coroutine
from .. import base_settings, NotifyUser

__author__ = "Lukas Reiter"
__copyright__ = "Copyright (C) 2024 Lukas Reiter"
__license__ = "GPLv3"

logger = logging.getLogger(__name__)


class RedisConnectionError(ConnectionError):
    def __init__(self):
        super().__init__("Connection to Redis server failed.")


async def publish(
        username: str,
        password: str,
        channel: str,
        message: str | Dict
):
    """
    Sends a message to the given message broker's channel.
    :param username: The username for the Redis server.
    :param password: The password for the Redis server.
    :param channel: The channel to which the caller wants to send the message.
    :param message: The message that shall be published.
    """
    r = await base_settings.create_redis(username=username, password=password)
    try:
        result = json.dumps(message) if isinstance(message, dict) else message
        await r.lpush(channel, result)
        logger.debug(f"Published message to channel {channel}.")
    except Exception as ex:
        logger.exception(ex)
    finally:
        await r.aclose()


async def subscribe(
        username: str,
        password: str,
        channel: str,
        callback: Callable[[Dict | str], Coroutine]
):
    """
    Subscribes to the given message broker's channel and calls the given callable.
    :param username: The username for the Redis server.
    :param password: The password for the Redis server.
    :param channel: The channel to which caller wants to subscribe.
    :param callback: The callback function that is called once messages are received.
    """
    r = await base_settings.create_redis(username=username, password=password)
    while True:
        try:
            message = await r.blpop(channel)
            chl, data = message
            if data is not None and chl.decode() == channel:
                logger.debug(f"Received message from channel {channel}")
                await callback(data.decode())
        except ConnectionError:
            logger.warning("Lost connection to Redis. Sleeping 10 seconds before trying to reconnect.")
            time.sleep(10)


async def notify_user(
        message: NotifyUser
):
    """
    Sends a message to the given user.
    """
    await publish(
        username=base_settings.redis_user_notify_user_write,
        password=base_settings.redis_password_notify_user_write,
        channel=base_settings.redis_notify_user_channel,
        message=message.json()
    )
