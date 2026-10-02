import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import net from 'node:net'
import { resolve } from 'node:path'

const projectRoot = process.cwd()
const pythonPath = resolve(projectRoot, '.venv', 'Scripts', 'python.exe')

if (!existsSync(pythonPath)) {
  console.error('Python environment not found. Create .venv and install requirements.txt first.')
  process.exit(1)
}

const getFreePort = async () => {
  const server = net.createServer()
  await new Promise((resolveListen, rejectListen) => {
    server.once('error', rejectListen)
    server.listen(0, '127.0.0.1', resolveListen)
  })
  const address = server.address()
  if (!address || typeof address === 'string') {
    throw new Error('Could not determine a free local API port.')
  }
  await new Promise((resolveClose, rejectClose) => server.close((error) => error ? rejectClose(error) : resolveClose()))
  return address.port
}

const apiPort = await getFreePort()
const environment = { ...process.env, SIGNAL_API_PORT: String(apiPort) }
const processes = [
  spawn(pythonPath, ['-m', 'uvicorn', 'backend.main:app', '--reload', '--host', '127.0.0.1', '--port', String(apiPort)], {
    cwd: projectRoot,
    env: environment,
    stdio: 'inherit',
  }),
  spawn(process.execPath, [resolve(projectRoot, 'node_modules', 'vite', 'bin', 'vite.js'), '--host', '127.0.0.1'], {
    cwd: projectRoot,
    env: environment,
    stdio: 'inherit',
  }),
]

let shuttingDown = false
const shutdown = (exitCode = 0) => {
  if (shuttingDown) return
  shuttingDown = true
  process.exitCode = exitCode
  for (const child of processes) {
    if (child.exitCode === null) child.kill()
  }
}

for (const child of processes) {
  child.on('error', (error) => {
    console.error('A development service could not start:', error.message)
    shutdown(1)
  })
  child.on('exit', (code) => {
    if (!shuttingDown) shutdown(code ?? 1)
  })
}

process.on('SIGINT', () => shutdown())
process.on('SIGTERM', () => shutdown())