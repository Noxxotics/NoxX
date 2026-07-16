# Noxx Private Chat

Privacy-first direct messaging starter with client-side AES-GCM message encryption, private invitation links, account/destructive PINs, responsive phone UI, and PWA support.

## Run locally

```cmd
npm install
npm start
```

Open `http://localhost:3000`.

## Destructive login

A normal PIN signs in. To permanently wipe an account, enter the destructive PIN in the PIN field and repeat it in the second PIN field. The correct password is also required. The app deletes the account instead of opening it.

## Install on iPhone

Deploy with HTTPS, open the site in Safari, tap Share, and choose **Add to Home Screen**. The included manifest, icons, safe-area layout, and service worker enable standalone PWA behavior.

## Railway deployment

1. Upload this folder to a GitHub repository.
2. In Railway, create a project and deploy from that repository.
3. Add a persistent volume mounted at `/data`.
4. Add variables:
   - `DATA_DIR=/data`
   - `NODE_ENV=production`
   - `JWT_SECRET=` followed by a long random value
5. Under Public Networking, generate a Railway domain.
6. Optionally add your own custom domain.

Do not deploy without a persistent volume, or the SQLite database may be lost during redeployment.

## Security limitations

This is not the audited SimpleX protocol. The server stores encrypted message payloads, while encryption keys stay in browser storage or exported backups. Metadata such as account records, conversation membership, timestamps, and connection activity remains visible to the server. Get an independent security audit before presenting it as production-secure.
