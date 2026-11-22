// Disposable application for the YAML example. Start it on a fresh SQLite file.
import { openSync, closeSync } from 'node:fs';
import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';

const { SETRYA_TEST_DB, SETRYA_SUBJECT_REF, SETRYA_READER_TOKEN, SETRYA_ERASER_TOKEN } = process.env;
if (!SETRYA_TEST_DB || !/^[a-f0-9]{64}$/.test(SETRYA_SUBJECT_REF ?? '') ||
    !SETRYA_READER_TOKEN || !SETRYA_ERASER_TOKEN || SETRYA_READER_TOKEN === SETRYA_ERASER_TOKEN) {
  throw Error('Set the database path, synthetic subject reference and separate test tokens.');
}
closeSync(openSync(SETRYA_TEST_DB, 'wx', 0o600));
const db = new DatabaseSync(SETRYA_TEST_DB);
db.exec('CREATE TABLE notes (id TEXT PRIMARY KEY, ticket TEXT, subject TEXT, body TEXT)');
const insert = db.prepare('INSERT INTO notes VALUES (?, ?, ?, ?)');
insert.run('note', 'ticket-204', SETRYA_SUBJECT_REF, 'Harbor-17');
insert.run('dispatch', 'ticket-204', 'team', 'Thursday');
const read = db.prepare('SELECT body FROM notes WHERE ticket = ? AND id = ?');
const erase = db.prepare('DELETE FROM notes WHERE ticket = ? AND subject = ?');

const server = createServer(async (req, res) => {
  const answer = req.method === 'POST' && req.url === '/answer';
  const deletion = req.method === 'DELETE' && req.url === '/erasure';
  if (!answer && !deletion) return res.writeHead(404).end();
  const token = answer ? SETRYA_READER_TOKEN : SETRYA_ERASER_TOKEN;
  if (req.headers.authorization !== 'Bearer ' + token) return res.writeHead(403).end();
  try {
    let body = '';
    for await (const data of req) {
      body += data;
      if (body.length > 8192) return res.writeHead(413).end();
    }
    const { conversation, question, subject_ref } = JSON.parse(body);
    if (conversation !== 'ticket-204') return res.writeHead(404).end();
    if (deletion) {
      if (subject_ref !== SETRYA_SUBJECT_REF) return res.writeHead(404).end();
      erase.run(conversation, subject_ref);
      return res.writeHead(204).end();
    }
    const key = question === 'When is dispatch?' ? 'dispatch' : 'note';
    const text = read.get(conversation, key)?.body ?? 'No matching note.';
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ caller: 'duty-agent', route: req.url, conversation, question, text }));
  } catch {
    res.writeHead(400).end();
  }
});

server.listen(0, '127.0.0.1', () => console.log('http://127.0.0.1:' + server.address().port));
