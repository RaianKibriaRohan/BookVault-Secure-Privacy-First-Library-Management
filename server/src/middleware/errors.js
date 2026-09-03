export function httpError(status, code, message) {
  const err = new Error(message)
  err.status = status
  err.code = code
  return err
}

export const asyncHandler = fn => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next)
}

export function notFound(req, res) {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: `No route for ${req.method} ${req.originalUrl}` } })
}

// eslint-disable-next-line no-unused-vars -- Express identifies error middleware by arity
export function errorHandler(err, req, res, next) {
  const status = err.status ?? 500
  const code = err.code ?? 'INTERNAL_ERROR'
  if (status >= 500) {
    console.error(`[error] ${req.method} ${req.originalUrl}`, err)
  }
  res.status(status).json({
    error: {
      code,
      message: status >= 500 ? 'An internal error occurred.' : err.message,
    },
  })
}
