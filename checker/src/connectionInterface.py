from enochecker3.enochecker import AsyncSocket
from enochecker3.types import (
	InternalErrorException,
	MumbleException,
)

from asyncio import StreamReader, StreamWriter
from asyncio.exceptions import TimeoutError
from logging import LoggerAdapter
from typing import cast, Optional, Any

import time

async def timed(promise: Any, logger: LoggerAdapter, ctx: str) -> Any:
    logger.debug("START: {}".format(ctx))
    start = time.time()
    result = await promise
    end = time.time()
    logger.debug("DONE:  {} (took {:.3f} seconds)".format(ctx, end - start))
    return result

class Session: # adapted from stldoctor to have a more pwntools-esque interface
	def __init__(self, socket: AsyncSocket, logger: LoggerAdapter) -> None:
		socket_tuple = cast(tuple[StreamReader, StreamWriter], socket)
		self.reader = socket_tuple[0]
		self.writer = socket_tuple[1]
		self.logger = logger

	async def recvuntil(self, target: bytes, ctx: Optional[str] = None) -> bytes:
		try:
			ctxstr = f"readuntil {target!r}" if ctx is None else ctx
			data = await timed(self.reader.readuntil(target), self.logger, ctx=ctxstr)
			msg = f"recv:  {data[:200]!r}{'..' if len(data) > 200 else ''}"
			self.logger.debug(msg)
			return data
		except TimeoutError:
			self.logger.critical(f"Service timed out while waiting for {target!r}")
			raise MumbleException("Service took too long to respond")

	async def recvline(self, ctx: Optional[str] = None) -> bytes:
		return await self.recvuntil(b"\n", ctx=ctx)

	async def recv(self, n: int, ctx: Optional[str] = None) -> bytes:
		try:
			ctxstr = f"reading {n} bytes" if ctx is None else ctx
			data = await timed(self.reader.readexactly(n), self.logger, ctx=ctxstr)
			msg = f"recv:  {data[:60]!r}{'..' if len(data) > 60 else ''}"
			self.logger.debug(msg)
			return data
		except TimeoutError:
			self.logger.critical(f"Service timed out while reading {n} bytes")
			raise MumbleException("Service took too long to respond")

	async def drain(self) -> None:
		await self.writer.drain()

	def send(self, data: bytes) -> None:
		msg = f"sending: {data[:200]!r}{'..' if len(data) > 200 else ''}"
		self.logger.debug(msg)
		self.writer.write(data)
	
	def sendline(self, data: bytes) -> None:
		self.send(data + b'\n')

	async def prepare(self) -> None:
		await self.recvuntil(prompt)

	async def exit(self) -> None:
		if self.closed:
			return
		# self.send(b"exit\n")
		await self.drain()
		# await self.recvuntil(b"bye!")
		await self.close()

	async def close(self) -> None:
		if self.closed:
			return
		self.closed = True
		self.writer.close()
		await self.writer.wait_closed()

