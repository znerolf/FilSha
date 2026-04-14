// FileShare Application - Optimized Version
class FileShareApp {
    constructor() {
        this.selectedFilesList = [];
        this.socket = null;
        this.uploadInProgress = false;
        this.currentFileId = null;
        this.fileQueue = [];
        this.currentFileIndex = 0;
        this.totalFiles = 0;
        this.uploadComplete = false;
        this.mobileCardsInitialized = false;
        
        this.init();
    }

    init() {
        document.addEventListener('DOMContentLoaded', () => {
            this.initializeComponents();
            this.setupEventListeners();
            this.initializeSocketIO();
        });
    }

    initializeComponents() {
        this.initializeTooltips();
        this.initializeTableSorting();
        this.initializeTableSearch();
        this.initializeModals();
        this.convertTablesToCards();
    }

    setupEventListeners() {
        // Window resize handler
        window.addEventListener('resize', this.debounce(() => {
            this.convertTablesToCards();
        }, 250));

        // Global click handlers for dynamic content
        document.addEventListener('click', this.handleGlobalClicks.bind(this));

        // Flash message auto-hide
        this.autoHideFlashMessages();
    }

    // ========== TOOLTIPS & UI COMPONENTS ==========

    initializeTooltips() {
        const tooltipElements = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltipElements.forEach(el => new bootstrap.Tooltip(el));
    }

    initializeTableSorting() {
        document.querySelectorAll('.sortable').forEach(header => {
            header.addEventListener('click', () => this.sortTable(header));
        });
    }

    sortTable(header) {
        const table = header.closest('table');
        const columnIndex = Array.from(header.parentNode.children).indexOf(header);
        const isActive = header.classList.contains('active');
        const isAsc = header.classList.contains('asc');

        // Reset headers
        table.querySelectorAll('.sortable').forEach(h => {
            h.classList.remove('active', 'asc', 'desc');
        });

        // Set new state
        header.classList.add('active');
        header.classList.toggle('asc', !isActive || !isAsc);
        header.classList.toggle('desc', isActive && isAsc);

        // Sort rows
        const rows = Array.from(table.querySelectorAll('tbody tr'));
        const direction = header.classList.contains('asc') ? 1 : -1;

        rows.sort((a, b) => {
            const aValue = a.children[columnIndex].textContent.trim();
            const bValue = b.children[columnIndex].textContent.trim();

            switch (header.dataset.sort) {
                case 'date':
                    return direction * (new Date(aValue) - new Date(bValue));
                case 'numeric':
                    return direction * (parseFloat(aValue) - parseFloat(bValue));
                default:
                    return direction * aValue.localeCompare(bValue);
            }
        });

        // Re-insert rows
        const tbody = table.querySelector('tbody');
        rows.forEach(row => tbody.appendChild(row));
    }

    initializeTableSearch() {
        document.querySelectorAll('.table-search').forEach(input => {
            input.addEventListener('input', this.debounce(() => {
                const tableId = input.dataset.table;
                const searchText = input.value.toLowerCase();
                
                this.filterTable(tableId, searchText);
            }, 300));
        });
    }

    filterTable(tableId, searchText) {
        const table = document.getElementById(tableId);
        if (!table) return;

        table.querySelectorAll('tbody tr').forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(searchText) ? '' : 'none';
        });
    }

    // ========== MODAL MANAGEMENT ==========

    initializeModals() {
        this.initializeDeleteModal();
        this.initializeRenameModal();
    }

    initializeDeleteModal() {
        const deleteModal = document.getElementById('deleteConfirmModal');
        if (deleteModal) {
            deleteModal.addEventListener('show.bs.modal', (event) => {
                const button = event.relatedTarget;
                const fileId = button.dataset.fileId;
                const filename = button.dataset.filename;

                document.getElementById('filename-to-delete').textContent = filename;
                document.getElementById('deleteFileForm').action = `/delete_file/${fileId}`;
            });
        }
    }

    initializeRenameModal() {
        const renameForm = document.getElementById('renameFileForm');
        if (renameForm) {
            renameForm.addEventListener('submit', (event) => {
                event.preventDefault();
                this.handleRenameFile();
            });
        }
    }

    async handleRenameFile() {
        const fileId = document.getElementById('file_id').value;
        const newFilename = document.getElementById('new_filename').value;

        try {
            const response = await fetch(`/rename_file/${fileId}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `new_filename=${encodeURIComponent(newFilename)}`
            });

            if (response.redirected) {
                window.location.href = response.url;
            }
        } catch (error) {
            console.error('Error renaming file:', error);
            this.showAlert('Error', 'Failed to rename file', 'error');
        }
    }

    // ========== FILE UPLOAD & MANAGEMENT ==========

    async handleFileUpload(event) {
        event.preventDefault();

        if (!this.selectedFilesList.length) {
            this.showAlert('Error', 'Please select files to upload', 'warning');
            return;
        }

        if (!this.validateFileSizes()) {
            return;
        }

        try {
            await this.startUploadProcess();
        } catch (error) {
            console.error('Upload error:', error);
            this.showAlert('Upload Error', 'An error occurred during upload', 'error');
        }
    }

    validateFileSizes() {
        const maxFileSize = 1024 * 1024 * 1024; // 1GB
        const oversizedFiles = this.selectedFilesList.filter(file => file.size > maxFileSize);

        if (oversizedFiles.length > 0) {
            const fileNames = oversizedFiles.map(file => file.name).join(', ');
            this.showAlert('File Size Error', `The following files exceed 1GB limit: ${fileNames}`, 'error');
            return false;
        }

        return true;
    }

    async startUploadProcess() {
        this.showUploadLoadingState(true);
        
        this.fileQueue = [...this.selectedFilesList];
        this.totalFiles = this.fileQueue.length;
        this.currentFileIndex = 0;
        this.uploadComplete = false;

        await this.uploadNextFile();
    }

    async uploadNextFile() {
        if (this.currentFileIndex >= this.fileQueue.length) {
            if (this.uploadComplete) {
                this.showUploadSuccess();
                this.selectedFilesList = [];
            }
            return;
        }

        this.currentFileId = Date.now().toString();
        this.uploadInProgress = true;

        const formData = new FormData(document.querySelector('form'));
        
        // Clear existing files and add all selected files
        if (formData.has('file')) {
            formData.delete('file');
        }

        this.fileQueue.forEach(file => {
            formData.append('file', file);
        });

        // Notify server about upload start
        this.socket.emit('upload_start', {
            user_id: window.currentUserId,
            file_id: this.currentFileId,
            filename: this.fileQueue.length > 1 ? `${this.fileQueue.length} files` : this.fileQueue[0].name,
            total_size: this.fileQueue.reduce((total, file) => total + file.size, 0),
            file_index: 0,
            total_files: this.fileQueue.length
        });

        await this.sendUploadRequest(formData);
    }

    async sendUploadRequest(formData) {
        try {
            const xhr = new XMLHttpRequest();
            
            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable && this.uploadInProgress) {
                    this.socket.emit('upload_progress_update', {
                        user_id: window.currentUserId,
                        file_id: this.currentFileId,
                        uploaded_size: e.loaded,
                        file_index: 0,
                        total_files: this.fileQueue.length
                    });
                }
            });

            xhr.onload = () => this.handleUploadResponse(xhr);
            xhr.onerror = () => this.handleUploadError('Network error during upload');

            xhr.open('POST', window.uploadUrl, true);
            xhr.send(formData);

        } catch (error) {
            this.handleUploadError('Upload request failed');
        }
    }

    handleUploadResponse(xhr) {
        this.showUploadLoadingState(false);

        if (xhr.status >= 200 && xhr.status < 300) {
            this.socket.emit('upload_complete', {
                user_id: window.currentUserId,
                file_id: this.currentFileId,
                file_index: 0,
                total_files: this.fileQueue.length
            });

            this.uploadComplete = true;
            this.currentFileIndex = this.fileQueue.length;
            this.showUploadSuccess();
        } else {
            this.handleUploadError('Upload failed with server error');
        }
    }

    handleUploadError(message) {
        this.showUploadLoadingState(false);
        this.uploadInProgress = false;
        this.currentFileId = null;
        this.showAlert('Upload Error', message, 'error');
    }

    // ========== UI HELPERS ==========

    showUploadLoadingState(show) {
        const uploadBtn = document.getElementById('upload-btn');
        const spinner = document.getElementById('upload-spinner');
        const dropZone = document.getElementById('drag-drop-area');
        const loadingMessage = document.getElementById('loading-message');

        if (uploadBtn) uploadBtn.disabled = show;
        if (spinner) spinner.classList.toggle('d-none', !show);
        if (dropZone) dropZone.classList.toggle('uploading', show);
        if (loadingMessage) loadingMessage.style.display = show ? 'block' : 'none';
    }

    showUploadSuccess() {
        const message = this.fileQueue.length > 1 ? 
            `All ${this.fileQueue.length} files uploaded successfully!` : 
            'File uploaded successfully!';

        this.showAlert('Success', message, 'success', () => {
            window.location.reload();
        });
    }

    showAlert(title, text, icon, callback = null) {
        Swal.fire({
            title,
            text,
            icon,
            confirmButtonText: 'OK'
        }).then((result) => {
            if (callback && result.isConfirmed) {
                callback();
            }
        });
    }

    autoHideFlashMessages() {
        setTimeout(() => {
            const flashMessage = document.getElementById('flash-message');
            if (flashMessage) {
                flashMessage.style.opacity = '0';
                setTimeout(() => {
                    flashMessage.style.display = 'none';
                }, 500);
            }
        }, 3000);
    }

    // ========== MOBILE RESPONSIVE ==========

    convertTablesToCards() {
        if (window.innerWidth <= 768 && !this.mobileCardsInitialized) {
            this.mobileCardsInitialized = true;
            this.createMobileCards('your-files-table', 'mobile-cards-your-files');
            this.createMobileCards('shared-files-table', 'mobile-cards-shared-files');
        } else if (window.innerWidth > 768 && this.mobileCardsInitialized) {
            this.mobileCardsInitialized = false;
            document.querySelectorAll('.mobile-cards-container').forEach(container => {
                container.style.display = 'none';
            });
            document.querySelectorAll('.table-responsive table').forEach(table => {
                table.style.display = 'table';
            });
        }
    }

    createMobileCards(tableId, containerId) {
        const table = document.getElementById(tableId);
        if (!table) return;

        table.style.display = 'none';

        let container = document.getElementById(containerId);
        if (!container) {
            container = document.createElement('div');
            container.id = containerId;
            container.className = 'mobile-cards-container';
            table.parentNode.insertBefore(container, table.nextSibling);
        } else {
            container.innerHTML = '';
            container.style.display = 'block';
        }

        const headers = Array.from(table.querySelectorAll('thead th')).map(th => 
            th.textContent.trim()
        );

        table.querySelectorAll('tbody tr').forEach(row => {
            const cells = row.querySelectorAll('td');
            if (cells.length === 0) return;

            const card = this.createMobileCard(headers, cells);
            container.appendChild(card);
        });

        this.setupMobileSearch(tableId, containerId);
    }

    createMobileCard(headers, cells) {
        const card = document.createElement('div');
        card.className = 'file-card';

        const filename = cells[0].textContent.trim();
        const status = cells[1].innerHTML;

        const cardHeader = document.createElement('div');
        cardHeader.className = 'file-card-header';
        cardHeader.innerHTML = `
            <div style="flex: 1; min-width: 0;">
                <h5 title="${filename}">${filename}</h5>
            </div>
            <div class="file-status">
                ${status}
                <i class="bi bi-chevron-down toggle-icon ms-2"></i>
            </div>
        `;

        const cardBody = document.createElement('div');
        cardBody.className = 'file-card-body';

        // Add table data rows
        for (let i = 2; i < cells.length - 1; i++) {
            if (headers[i] && cells[i].textContent.trim()) {
                const rowDiv = document.createElement('div');
                rowDiv.className = 'file-card-row';
                rowDiv.innerHTML = `
                    <span class="text-muted">${headers[i]}:</span>
                    <span>${cells[i].innerHTML}</span>
                `;
                cardBody.appendChild(rowDiv);
            }
        }

        // Add action buttons
        const actionsCell = cells[cells.length - 1];
        if (actionsCell && actionsCell.innerHTML.trim()) {
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'file-actions';
            actionsDiv.innerHTML = actionsCell.innerHTML;
            cardBody.appendChild(actionsDiv);
        }

        cardHeader.addEventListener('click', () => {
            cardBody.classList.toggle('active');
            cardHeader.classList.toggle('active');
        });

        card.appendChild(cardHeader);
        card.appendChild(cardBody);
        return card;
    }

    setupMobileSearch(tableId, containerId) {
        const searchInput = document.querySelector(`input[data-table="${tableId}"]`);
        if (!searchInput) return;

        searchInput.addEventListener('input', this.debounce(() => {
            const searchText = searchInput.value.toLowerCase();
            const mobileContainer = document.getElementById(containerId);

            if (mobileContainer) {
                mobileContainer.querySelectorAll('.file-card').forEach(card => {
                    const cardText = card.textContent.toLowerCase();
                    card.style.display = cardText.includes(searchText) ? '' : 'none';
                });
            }
        }, 300));
    }

    // ========== GLOBAL EVENT HANDLERS ==========

    handleGlobalClicks(event) {
        // Rename button clicks
        if (event.target.closest('.rename-btn')) {
            const renameBtn = event.target.closest('.rename-btn');
            this.handleRenameButtonClick(renameBtn);
        }

        // Delete button clicks
        if (event.target.closest('[data-bs-target="#deleteConfirmModal"]')) {
            const deleteBtn = event.target.closest('[data-bs-target="#deleteConfirmModal"]');
            this.handleDeleteButtonClick(deleteBtn);
        }
    }

    handleRenameButtonClick(button) {
        const fileId = button.dataset.fileId;
        const currentFilename = button.dataset.currentFilename;

        document.getElementById('file_id').value = fileId;
        document.getElementById('current_filename').value = currentFilename;
        document.getElementById('new_filename').value = currentFilename;

        const modal = new bootstrap.Modal(document.getElementById('renameFileModal'));
        modal.show();
    }

    handleDeleteButtonClick(button) {
        const fileId = button.dataset.fileId;
        const filename = button.dataset.filename;

        document.getElementById('filename-to-delete').textContent = filename;
        document.getElementById('deleteFileForm').action = `/delete_file/${fileId}`;

        const modal = new bootstrap.Modal(document.getElementById('deleteConfirmModal'));
        modal.show();
    }

    // ========== SOCKET.IO ==========

    initializeSocketIO() {
        this.socket = io();

        this.socket.on('connect', () => {
            this.socket.emit('join', { user_id: window.currentUserId });
        });

        this.socket.on('upload_progress', (data) => {
            this.updateProgressBar(data);
        });
    }

    updateProgressBar(data) {
        const progressContainer = document.getElementById('upload-progress-container');
        const progressBar = document.getElementById('upload-progress-bar');
        const progressPercentage = document.getElementById('progress-percentage');
        const progressFilename = document.getElementById('progress-filename');
        const uploadSpeed = document.getElementById('upload-speed');
        const uploadSize = document.getElementById('upload-size');

        if (!progressContainer || !progressBar) return;

        progressContainer.classList.remove('d-none');

        const progress = Math.round(data.progress);
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
        progressPercentage.textContent = `${progress}%`;

        if (data.total_files > 1) {
            progressFilename.textContent = data.status === 'completed' ?
                `All ${data.total_files} files uploaded successfully as a ZIP archive!` :
                `Uploading ${data.total_files} files as a ZIP archive...`;
        } else {
            progressFilename.textContent = data.status === 'completed' ?
                `${data.filename} uploaded successfully!` :
                `Uploading ${data.filename}...`;
        }

        if (uploadSpeed) uploadSpeed.textContent = this.formatSpeed(data.speed);
        if (uploadSize) uploadSize.textContent = `${this.formatFileSize(data.uploaded_size)} / ${this.formatFileSize(data.total_size)}`;

        if (data.status === 'completed') {
            progressBar.classList.remove('progress-bar-animated');
            if (uploadSpeed) uploadSpeed.textContent = 'Upload complete!';
            this.uploadInProgress = false;
            this.currentFileId = null;
        }
    }

    // ========== UTILITY FUNCTIONS ==========

    formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    formatSpeed(bytesPerSecond) {
        if (bytesPerSecond < 1024) {
            return Math.round(bytesPerSecond) + ' B/s';
        } else if (bytesPerSecond < 1024 * 1024) {
            return (bytesPerSecond / 1024).toFixed(1) + ' KB/s';
        } else {
            return (bytesPerSecond / (1024 * 1024)).toFixed(1) + ' MB/s';
        }
    }

    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
}

// Initialize the application
const fileShareApp = new FileShareApp();

// Export for global access if needed
window.FileShareApp = fileShareApp;