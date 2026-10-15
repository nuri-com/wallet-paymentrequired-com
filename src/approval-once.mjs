


















const inFlight = new Map();

export async function oncePerSession(sessionId, run) {
  const running = inFlight.get(sessionId);
  if (running) return await running;
  const promise = Promise.resolve().then(run).finally(() => {
    if (inFlight.get(sessionId) === promise) inFlight.delete(sessionId);
  });
  inFlight.set(sessionId, promise);
  return await promise;
}
