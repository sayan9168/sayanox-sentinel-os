# Screenshots & demo GIF

Put real product visuals here, then link them from the root `README.md`.

## Suggested files

| File | What to capture |
|------|-----------------|
| `dashboard.png` | Main metrics dashboard (CPU/RAM charts) |
| `terminal.png` | Web terminal panel |
| `honeypot.png` | Honeypot status / logs |
| `demo.gif` | 5–15s walkthrough (optional, best for stars) |

## How to capture

1. Run the app:
   ```bash
   cd ai-security-dashboard
   docker compose up --build
   ```
2. Open `http://localhost:3000`
3. Screenshot or record (OBS / ShareX / Kap)
4. Save files into this folder and commit:
   ```bash
   git add docs/screenshots/
   git commit -m "docs: add product screenshots"
   git push
   ```

Root README already points at:

```markdown
![Dashboard](docs/screenshots/dashboard.png)
![Demo](docs/screenshots/demo.gif)
```
