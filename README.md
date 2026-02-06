# ☁️ Cloudflare R2 Stream Downloader & Manager

A high-performance, serverless download manager built on **Cloudflare Workers**, **Durable Objects**, and **R2 Storage**.

This tool allows you to fetch large files from remote URLs and stream them directly into your R2 bucket. It uses zero-copy streaming to keep memory usage extremely low (works within 128MB limits) and optimizes R2 costs by using a single Write operation per file.

## ✨ Features

*   **🚀 Streaming Uploads:** Pipes remote `fetch` bodies directly to R2 using `TransformStream`. Never holds the full file in memory.
*   **💰 Cost Optimized:** Uses `FixedLengthStream` to ensure R2 counts the upload as **1 Class A Operation** (instead of hundreds of multipart chunks).
*   **🔄 Background Processing:** Uses **Durable Objects** to keep downloads running reliably in the background, even if the client disconnects.
*   **💾 Smart Caching:** Checks if a file already exists in R2 before starting a download to save bandwidth and operations.
*   **🖥️ Admin Dashboard:** Built-in HTML/JS Single Page Application (SPA) to manage downloads, view history, and delete files.
*   **📤 Direct Uploads:** Supports direct binary uploads from your computer to R2 via the dashboard.
*   **🔒 Authentication:** Simple API Key protection for all routes.

## 🛠️ Prerequisites

*   A Cloudflare Account.
*   `wrangler` CLI installed (`npm install -g wrangler`).

## ⚙️ Configuration (`wrangler.toml`)

Create a `wrangler.toml` file in your project root.


```toml
name = "r2-downloader"
main = "src/_worker.js"
compatibility_date = "2026-01-01"

# R2 bucket binding
[[r2_buckets]]
binding = "DRIVE_BUCKET"
bucket_name = "my-drive-bucket"
preview_bucket_name = "my-drive-bucket-preview"  # Optional: separate bucket for dev

# Durable Objects configuration
[durable_objects]
bindings = [
  { name = "DOWNLOAD_MANAGER", class_name = "DownloadManager" }
]

# Durable Objects migration
[[migrations]]
tag = "<v1>"
new_sqlite_classes = ["DownloadManager"]

# Optional: Environment variables
[vars]
# Add any environment variables here
```

### Reference:
- https://developers.cloudflare.com/durable-objects/reference/durable-objects-migrations/


## 🧪 Local Development

1. **Create `.dev.vars`**
  ```
  APIKEYSECRET=yourapi
  ```
2. **Start Server**
  ```bash
  npx wrangler dev -c ./wrangler.workers.toml
  ```


## 🚀 Deployment

1.  **Create the R2 Bucket:**
    ```bash
    npx wrangler r2 bucket create my-drive-bucket
    ```

2.  **Set the API Key (Recommended):**

    - Workers
    ```bash
    npx wrangler secret put APIKEYSECRET  -c ./wrangler.workers.toml
    # Enter your desired password when prompted
    ```
    - Pages
    ```bash
    npx wrangler pages secret put APIKEYSECRET
    ```

3.  **Deploy:**
    - Workers
    
    ```bash
    npx wrangler deploy -c ./wrangler.workers.toml
    ```
    - Pages

    ```bash
    npx wrangler pages deploy 
    ```

## 🖥️ Usage

### Admin Panel
Visit your worker URL in a browser:
`https://r2-stream-downloader.your-subdomain.workers.dev/?key=YOUR_SECRET_KEY`

*   **Remote Downloader:** Paste a URL to download it to R2.
*   **Direct Upload:** Select a file from your computer to stream to R2.
*   **Library:** View, download, or delete files currently in your bucket.

### API Reference

All requests must include `x-api-key: YOUR_KEY` header or `?key=YOUR_KEY` query param.

#### 1. Start Download
**POST** `/download`

```json
{
  "sourceUrl": "https://example.com/video.mp4",
  "filename": "my-video.mp4",
  "force": false 
}
```
*   `force`: (Optional) Set to `true` to overwrite if file exists.

#### 2. Check Status
**GET** `/status/:jobId`
Returns progress percentage, bytes downloaded, and status (`downloading`, `completed`, `failed`).

#### 3. Get Download Link
**GET** `/get/:filename`
Returns a stream of the file from R2 with `Content-Disposition: attachment`.

#### 4. Direct Upload
**PUT** `/upload?filename=image.png`
Body: Raw binary data.

#### 5. List Files
**GET** `/list`
Returns JSON array of files in the bucket.

#### 6. Delete File
**DELETE** `/delete?filename=image.png`

## 🧠 How it Works

1.  **The Pipeline:**
    `Remote URL` -> `fetch()` -> `TransformStream (Counting)` -> `FixedLengthStream` -> `R2 put()`
2.  **Memory Safety:**
    By using streams, the Worker never loads the file into RAM. It only holds a tiny chunk (approx 64KB) at any given millisecond.
3.  **Durable Object Life:**
    We use `state.waitUntil()` inside the Durable Object. This tells Cloudflare "Don't freeze this instance, I'm doing work," allowing the download to continue even after the HTTP response is sent to the user.

## 📝 License

MIT License. Feel free to modify and use for your own projects.
