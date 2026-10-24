// TrustVault Enterprise SaaS Client Scripts
document.addEventListener('DOMContentLoaded', () => {
    // 1. Mobile Sidebar Toggle
    const mobileToggleBtn = document.getElementById('mobileSidebarToggle');
    const sidebar = document.getElementById('sidebarNav');
    const backdrop = document.getElementById('sidebarBackdrop');

    if (mobileToggleBtn && sidebar) {
        mobileToggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('show');
            if (backdrop) backdrop.classList.toggle('show');
        });
    }

    if (backdrop) {
        backdrop.addEventListener('click', () => {
            sidebar.classList.remove('show');
            backdrop.classList.remove('show');
        });
    }

    // Close sidebar on link click when on mobile
    const navLinks = sidebar ? sidebar.querySelectorAll('.nav-link-custom') : [];
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            if (window.innerWidth < 992 && sidebar) {
                sidebar.classList.remove('show');
                if (backdrop) backdrop.classList.remove('show');
            }
        });
    });

    // 2. Drag & Drop Upload Zone Handler
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('document_file');
    const previewContainer = document.getElementById('filePreview');
    const fileNameSpan = document.getElementById('selectedFileName');
    const fileSizeSpan = document.getElementById('selectedFileSize');
    const removeFileBtn = document.getElementById('removeFileBtn');

    if (dropzone && fileInput) {
        // Trigger file input click when dropzone is clicked
        dropzone.addEventListener('click', (e) => {
            if (e.target !== removeFileBtn && !removeFileBtn?.contains(e.target)) {
                fileInput.click();
            }
        });

        // Drag over / leave effects
        ['dragenter', 'dragover'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.add('drag-over');
            });
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropzone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropzone.classList.remove('drag-over');
            });
        });

        // Drop event
        dropzone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            if (files && files.length > 0) {
                fileInput.files = files;
                updateFilePreview(files[0]);
            }
        });

        // Input change event
        fileInput.addEventListener('change', () => {
            if (fileInput.files && fileInput.files.length > 0) {
                updateFilePreview(fileInput.files[0]);
            }
        });

        // Remove selected file
        if (removeFileBtn) {
            removeFileBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                fileInput.value = '';
                if (previewContainer) previewContainer.classList.add('d-none');
            });
        }
    }

    function updateFilePreview(file) {
        if (!previewContainer) return;
        if (fileNameSpan) fileNameSpan.textContent = file.name;
        if (fileSizeSpan) {
            const sizeKb = (file.size / 1024).toFixed(1);
            fileSizeSpan.textContent = `${sizeKb} KB`;
        }
        previewContainer.classList.remove('d-none');

        // Autofill title if empty
        const titleInput = document.getElementById('title');
        if (titleInput && !titleInput.value) {
            // Strip extension
            const cleanTitle = file.name.replace(/\.[^/.]+$/, "");
            titleInput.value = cleanTitle;
        }
    }

    // 3. Auto-dismiss alerts
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) bsAlert.close();
        }, 6000);
    });
});
