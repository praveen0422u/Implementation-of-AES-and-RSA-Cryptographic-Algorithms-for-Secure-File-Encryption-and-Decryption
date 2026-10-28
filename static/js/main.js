/**
 * main.js
 * Client-side Controller for CNS Cryptographic Guard
 * 
 * SECURITY RULES:
 * 1. Cryptographic keys are never stored in localStorage or sessionStorage.
 * 2. Raw keys, private-key contents, and plaintext data are never logged to console.
 * 3. All cryptographic operations use real backend Flask endpoints.
 */

const MAX_FILE_SIZE_BYTES = 16 * 1024 * 1024; // 16 MB limit

document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initHealthCheck();
    initFileDropZone("encrypt");
    initFileDropZone("decrypt");
    initKeyFileUploads();
    initEncryptForm();
    initDecryptForm();
    initKeyGenerator();
});

// ==============================================================================
// TAB NAVIGATION
// ==============================================================================

function initTabs() {
    const tabButtons = document.querySelectorAll(".tab-button");
    const panels = document.querySelectorAll(".tab-panel");

    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetPanelId = btn.getAttribute("aria-controls");

            tabButtons.forEach(b => {
                b.classList.remove("active");
                b.setAttribute("aria-selected", "false");
                b.setAttribute("tabindex", "-1");
            });

            panels.forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            btn.setAttribute("aria-selected", "true");
            btn.setAttribute("tabindex", "0");

            const activePanel = document.getElementById(targetPanelId);
            if (activePanel) {
                activePanel.classList.add("active");
            }
        });
    });
}

function switchTab(panelId) {
    const tabBtn = document.querySelector(`.tab-button[aria-controls="${panelId}"]`);
    if (tabBtn) {
        tabBtn.click();
    }
}

// ==============================================================================
// LIVE HEALTH CHECK PING
// ==============================================================================

async function initHealthCheck() {
    const statusDot = document.getElementById("status-dot");
    const statusLabel = document.getElementById("status-label");

    try {
        const response = await fetch("/health");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);

        const data = await response.json();
        if (data.status === "healthy") {
            statusDot.classList.remove("error");
            statusDot.classList.add("active");
            statusLabel.textContent = `Online • ${data.crypto_engine}`;
            statusLabel.title = `Service: ${data.service} (v${data.version})`;
        } else {
            throw new Error("System unhealthy");
        }
    } catch (err) {
        statusDot.classList.remove("active");
        statusDot.classList.add("error");
        statusLabel.textContent = "Offline / Server Error";
    }
}

// ==============================================================================
// DRAG & DROP AND FILE SELECTION
// ==============================================================================

function initFileDropZone(mode) {
    const dropzone = document.getElementById(`${mode}-dropzone`);
    const fileInput = document.getElementById(`${mode}-file-input`);
    const promptArea = document.getElementById(`${mode}-drop-prompt`);
    const previewArea = document.getElementById(`${mode}-file-preview`);
    const previewName = document.getElementById(`${mode}-preview-name`);
    const previewSize = document.getElementById(`${mode}-preview-size`);
    const clearBtn = document.getElementById(`${mode}-file-clear`);
    const alertBox = document.getElementById(`${mode}-alert`);

    if (!dropzone || !fileInput) return;

    // Trigger file dialog on click
    dropzone.addEventListener("click", (e) => {
        if (e.target.closest("#" + `${mode}-file-clear`)) return;
        fileInput.click();
    });

    // Keyboard accessibility
    dropzone.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            fileInput.click();
        }
    });

    // Drag-over styling
    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    // File dropped
    dropzone.addEventListener("drop", (e) => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            handleSelectedFile(files[0], mode);
        }
    });

    // File selected via dialog
    fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleSelectedFile(fileInput.files[0], mode);
        }
    });

    // Clear file selection
    if (clearBtn) {
        clearBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            fileInput.value = "";
            promptArea.classList.remove("hidden");
            previewArea.classList.add("hidden");
            hideAlert(alertBox);
        });
    }

    function handleSelectedFile(file, m) {
        hideAlert(alertBox);

        if (m === "decrypt" && !file.name.toLowerCase().endsWith(".sfe")) {
            showAlert(alertBox, "Invalid file format: Please select a valid .sfe encrypted package for decryption.", "error");
            return;
        }

        if (file.size > MAX_FILE_SIZE_BYTES) {
            showAlert(alertBox, `File exceeds the 16MB limit (${formatBytes(file.size)}). Please choose a smaller file.`, "error");
            fileInput.value = "";
            return;
        }

        // Set input file if dropped
        const dt = new DataTransfer();
        dt.items.add(file);
        fileInput.files = dt.files;

        // Display preview
        previewName.textContent = file.name;
        previewSize.textContent = formatBytes(file.size);
        promptArea.classList.add("hidden");
        previewArea.classList.remove("hidden");
    }
}

// ==============================================================================
// KEY FILE UPLOAD PARSERS
// ==============================================================================

function initKeyFileUploads() {
    // Encrypt Tab: Public Key File Upload
    const encKeyFileInput = document.getElementById("encrypt-pubkey-file");
    const encKeyText = document.getElementById("encrypt-pubkey-text");

    if (encKeyFileInput && encKeyText) {
        encKeyFileInput.addEventListener("change", () => {
            if (encKeyFileInput.files && encKeyFileInput.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    encKeyText.value = e.target.result.trim();
                };
                reader.readAsText(encKeyFileInput.files[0]);
            }
        });
    }

    // Decrypt Tab: Private Key File Upload
    const decKeyFileInput = document.getElementById("decrypt-privkey-file");
    const decKeyText = document.getElementById("decrypt-privkey-text");

    if (decKeyFileInput && decKeyText) {
        decKeyFileInput.addEventListener("change", () => {
            if (decKeyFileInput.files && decKeyFileInput.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    decKeyText.value = e.target.result.trim();
                };
                reader.readAsText(decKeyFileInput.files[0]);
            }
        });
    }
}

// ==============================================================================
// ENCRYPTION CONTROLLER (POST /api/encrypt)
// ==============================================================================

function initEncryptForm() {
    const form = document.getElementById("encrypt-form");
    const fileInput = document.getElementById("encrypt-file-input");
    const pubKeyText = document.getElementById("encrypt-pubkey-text");
    const submitBtn = document.getElementById("btn-submit-encrypt");
    const progress = document.getElementById("encrypt-progress");
    const alertBox = document.getElementById("encrypt-alert");

    // Result card elements
    const placeholder = document.getElementById("encrypt-result-placeholder");
    const resultBox = document.getElementById("encrypt-result-box");
    const badge = document.getElementById("encrypt-result-badge");
    const resPkgName = document.getElementById("res-enc-pkgname");
    const downloadBtn = document.getElementById("btn-download-sfe");

    if (!form) return;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideAlert(alertBox);

        // Validation
        if (!fileInput.files || fileInput.files.length === 0) {
            showAlert(alertBox, "Validation error: Please select a file to encrypt.", "error");
            return;
        }

        const pubKey = pubKeyText.value.trim();
        if (!pubKey) {
            showAlert(alertBox, "Validation error: Recipient RSA public key is required.", "error");
            pubKeyText.focus();
            return;
        }

        const file = fileInput.files[0];
        if (file.size > MAX_FILE_SIZE_BYTES) {
            showAlert(alertBox, `Validation error: File exceeds 16MB limit (${formatBytes(file.size)}).`, "error");
            return;
        }

        // Prepare multipart form data
        const formData = new FormData();
        formData.append("file", file);
        formData.append("public_key", pubKey);

        // Set UI loading state
        submitBtn.disabled = true;
        progress.classList.remove("hidden");

        try {
            const response = await fetch("/api/encrypt", {
                method: "POST",
                body: formData,
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `Server responded with HTTP ${response.status}`);
            }

            // Read encrypted .sfe blob
            const blob = await response.blob();
            const sfeFileName = `${file.name.substring(0, file.name.lastIndexOf('.')) || file.name}.sfe`;
            const downloadUrl = URL.createObjectURL(blob);

            // Automatically trigger download
            triggerDownload(downloadUrl, sfeFileName);

            // Update result display
            placeholder.classList.add("hidden");
            resultBox.classList.remove("hidden");
            badge.textContent = "Sealed (.sfe)";
            badge.className = "badge badge-accent";
            resPkgName.textContent = sfeFileName;
            downloadBtn.href = downloadUrl;
            downloadBtn.download = sfeFileName;

            showAlert(alertBox, `Success! File encrypted into ${sfeFileName} and download triggered.`, "success");

        } catch (err) {
            showAlert(alertBox, `Encryption failed: ${err.message}`, "error");
        } finally {
            submitBtn.disabled = false;
            progress.classList.add("hidden");
        }
    });
}

// ==============================================================================
// DECRYPTION CONTROLLER (POST /api/decrypt)
// ==============================================================================

function initDecryptForm() {
    const form = document.getElementById("decrypt-form");
    const fileInput = document.getElementById("decrypt-file-input");
    const privKeyText = document.getElementById("decrypt-privkey-text");
    const passphraseInput = document.getElementById("decrypt-passphrase");
    const submitBtn = document.getElementById("btn-submit-decrypt");
    const progress = document.getElementById("decrypt-progress");
    const alertBox = document.getElementById("decrypt-alert");

    // Result card elements
    const placeholder = document.getElementById("decrypt-result-placeholder");
    const resultBox = document.getElementById("decrypt-result-box");
    const badge = document.getElementById("decrypt-result-badge");
    const resFilename = document.getElementById("res-dec-filename");
    const resFilesize = document.getElementById("res-dec-filesize");
    const downloadBtn = document.getElementById("btn-download-decrypted");

    if (!form) return;

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        hideAlert(alertBox);

        // Validation
        if (!fileInput.files || fileInput.files.length === 0) {
            showAlert(alertBox, "Validation error: Please select an .sfe package to decrypt.", "error");
            return;
        }

        const privKey = privKeyText.value.trim();
        if (!privKey) {
            showAlert(alertBox, "Validation error: Recipient RSA private key is required.", "error");
            privKeyText.focus();
            return;
        }

        const file = fileInput.files[0];
        if (!file.name.toLowerCase().endsWith(".sfe")) {
            showAlert(alertBox, "Validation error: Selected file must be an .sfe encrypted package.", "error");
            return;
        }

        // Prepare multipart form data
        const formData = new FormData();
        formData.append("file", file);
        formData.append("private_key", privKey);
        const passphrase = passphraseInput.value.trim();
        if (passphrase) {
            formData.append("passphrase", passphrase);
        }

        // Set UI loading state
        submitBtn.disabled = true;
        progress.classList.remove("hidden");

        try {
            const response = await fetch("/api/decrypt", {
                method: "POST",
                body: formData,
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || `Server responded with HTTP ${response.status}`);
            }

            // Extract original filename from header or fallback
            let restoredName = response.headers.get("X-Decrypted-Filename");
            if (!restoredName) {
                const disposition = response.headers.get("Content-Disposition");
                if (disposition && disposition.includes("filename=")) {
                    restoredName = disposition.split("filename=")[1].replace(/["']/g, "").trim();
                }
            }
            if (!restoredName) {
                restoredName = "decrypted_file.bin";
            }

            const blob = await response.blob();
            const downloadUrl = URL.createObjectURL(blob);

            // Trigger download
            triggerDownload(downloadUrl, restoredName);

            // Update result display
            placeholder.classList.add("hidden");
            resultBox.classList.remove("hidden");
            badge.textContent = "Verified";
            badge.className = "badge badge-accent";
            resFilename.textContent = restoredName;
            resFilesize.textContent = formatBytes(blob.size);
            downloadBtn.href = downloadUrl;
            downloadBtn.download = restoredName;

            showAlert(alertBox, `Success! Authenticated integrity confirmed and ${restoredName} restored.`, "success");

        } catch (err) {
            showAlert(alertBox, `Decryption failed: ${err.message}`, "error");
        } finally {
            submitBtn.disabled = false;
            progress.classList.add("hidden");
        }
    });
}

// ==============================================================================
// RSA KEY PAIR GENERATOR (POST /api/keys/generate)
// ==============================================================================

function initKeyGenerator() {
    const keySizeSelect = document.getElementById("select-key-size");
    const generateBtn = document.getElementById("btn-trigger-keygen");
    const progress = document.getElementById("keygen-progress");
    const alertBox = document.getElementById("keys-alert");
    const outputArea = document.getElementById("keys-output-area");

    const pubKeyText = document.getElementById("output-public-pem");
    const privKeyText = document.getElementById("output-private-pem");
    const bitsBadge = document.getElementById("pubkey-bits-badge");

    const btnDownloadPub = document.getElementById("btn-download-pubkey");
    const btnDownloadPriv = document.getElementById("btn-download-privkey");
    const btnCopyPub = document.getElementById("btn-copy-pubkey");
    const btnCopyPriv = document.getElementById("btn-copy-privkey");
    const btnUsePub = document.getElementById("btn-use-pubkey-encrypt");
    const btnUsePriv = document.getElementById("btn-use-privkey-decrypt");

    if (!generateBtn) return;

    generateBtn.addEventListener("click", async () => {
        hideAlert(alertBox);
        const keySize = parseInt(keySizeSelect.value, 10) || 3072;

        generateBtn.disabled = true;
        progress.classList.remove("hidden");

        try {
            const response = await fetch("/api/keys/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ key_size: keySize }),
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.error || "Failed to generate keys.");
            }

            const data = await response.json();

            // Populate textareas
            pubKeyText.value = data.public_key;
            privKeyText.value = data.private_key;
            bitsBadge.textContent = `${data.key_size}-bit`;

            outputArea.classList.remove("hidden");
            showAlert(alertBox, `Successfully generated ${data.key_size}-bit RSA key pair via CSPRNG.`, "success");

        } catch (err) {
            showAlert(alertBox, `Key generation error: ${err.message}`, "error");
        } finally {
            generateBtn.disabled = false;
            progress.classList.add("hidden");
        }
    });

    // Key downloads
    btnDownloadPub.addEventListener("click", () => {
        if (!pubKeyText.value) return;
        downloadTextAsFile(pubKeyText.value, "public_key.pem");
    });

    btnDownloadPriv.addEventListener("click", () => {
        if (!privKeyText.value) return;
        downloadTextAsFile(privKeyText.value, "private_key.pem");
    });

    // Key copy actions
    btnCopyPub.addEventListener("click", () => {
        copyToClipboard(pubKeyText.value, btnCopyPub, "Copied Public Key!");
    });

    btnCopyPriv.addEventListener("click", () => {
        copyToClipboard(privKeyText.value, btnCopyPriv, "Copied Private Key!");
    });

    // Shortcut routing to Encrypt / Decrypt tabs
    btnUsePub.addEventListener("click", () => {
        const encText = document.getElementById("encrypt-pubkey-text");
        if (encText && pubKeyText.value) {
            encText.value = pubKeyText.value;
            switchTab("panel-encrypt");
            encText.scrollIntoView({ behavior: "smooth" });
        }
    });

    btnUsePriv.addEventListener("click", () => {
        const decText = document.getElementById("decrypt-privkey-text");
        if (decText && privKeyText.value) {
            decText.value = privKeyText.value;
            switchTab("panel-decrypt");
            decText.scrollIntoView({ behavior: "smooth" });
        }
    });
}

// ==============================================================================
// UTILITY FUNCTIONS
// ==============================================================================

function showAlert(el, message, type = "info") {
    if (!el) return;
    el.textContent = message;
    el.className = `alert-box alert-${type}`;
    el.classList.remove("hidden");
}

function hideAlert(el) {
    if (!el) return;
    el.classList.add("hidden");
}

function formatBytes(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function triggerDownload(url, filename) {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function downloadTextAsFile(text, filename) {
    const blob = new Blob([text], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    triggerDownload(url, filename);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function copyToClipboard(text, buttonEl, successText) {
    if (!navigator.clipboard) {
        // Fallback
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
    } else {
        navigator.clipboard.writeText(text);
    }

    const originalText = buttonEl.textContent;
    buttonEl.textContent = successText;
    buttonEl.disabled = true;
    setTimeout(() => {
        buttonEl.textContent = originalText;
        buttonEl.disabled = false;
    }, 2000);
}
