(() => {
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const filePreview = document.getElementById("filePreview");
    const filePreviewName = document.getElementById("filePreviewName");
    const filePreviewMeta = document.getElementById("filePreviewMeta");
    const uploadForm = document.getElementById("uploadForm");
    const uploadBtn = document.getElementById("uploadBtn");
    const progressFill = document.getElementById("progressFill");
    const uploadStatus = document.getElementById("uploadStatus");

    if (!dropZone || !fileInput || !uploadForm) return;

    function updateFilePreview(file) {
        if (!file) return;

        if (!file.name.toLowerCase().endsWith(".csv")) {
            window.alert("Only CSV files are supported.");
            fileInput.value = "";
            filePreview.hidden = true;
            uploadStatus.textContent = "Awaiting valid CSV";
            progressFill.style.width = "8%";
            return;
        }

        const sizeInKb = (file.size / 1024).toFixed(2);
        filePreview.hidden = false;
        filePreviewName.textContent = file.name;
        filePreviewMeta.textContent = `${sizeInKb} KB ready for scoring`;
        uploadStatus.textContent = "File staged";
        progressFill.style.width = "42%";
    }

    ["dragenter", "dragover"].forEach((eventName) => {
        dropZone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropZone.classList.add("dragover");
        });
    });

    ["dragleave", "dragend", "drop"].forEach((eventName) => {
        dropZone.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropZone.classList.remove("dragover");
        });
    });

    dropZone.addEventListener("drop", (event) => {
        const [file] = event.dataTransfer.files;
        if (!file) return;
        fileInput.files = event.dataTransfer.files;
        updateFilePreview(file);
    });

    fileInput.addEventListener("change", () => {
        const [file] = fileInput.files;
        updateFilePreview(file);
    });

    uploadForm.addEventListener("submit", () => {
        if (!fileInput.files.length) return;
        uploadBtn.disabled = true;
        uploadBtn.innerHTML = "<span>Processing traffic...</span>";
        uploadStatus.textContent = "Upload submitted";
        progressFill.style.width = "100%";
    });
})();
