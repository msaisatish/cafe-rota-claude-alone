# Café rota

A shift rota for one small café. The manager plans and publishes the week. Staff see only their own shifts and ask for swaps, and the manager approves or turns them down.

## Running it

You need Node.js version 22 or newer (https://nodejs.org).

- **Windows:** double-click `start.bat`.
- **Any computer:** open a terminal in this folder and run `npm install` once, then `npm start`.

Then open http://localhost:3000. The first time, you'll be asked to create the manager account.

To stop the app, close the window or press Ctrl+C.

## Where the data lives

Everything is saved in `data/rota.db`, a single SQLite database file. Copy that file to back up the rota. If you delete it, the app starts again from empty.

## Settings (optional)

- `PORT`: which port to use (the default is 3000).
- `DB_FILE`: where to keep the database file.

## How it is built

Node.js with Express. The pages are plain HTML made on the server and work on phones. The database is SQLite through Node's built-in `node:sqlite`. Passwords are stored as scrypt hashes, and sign-ins are kept in the database for 30 days.
