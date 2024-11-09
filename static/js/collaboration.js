// Initialize TinyMCE for rich text editing
function initTinyMCE(selector) {
    tinymce.init({
        selector: selector,
        height: 300,
        menubar: false,
        plugins: [
            'advlist autolink lists link image charmap print preview anchor',
            'searchreplace visualblocks code fullscreen',
            'insertdatetime media table paste code help wordcount'
        ],
        toolbar: 'undo redo | formatselect | bold italic backcolor | \
                alignleft aligncenter alignright alignjustify | \
                bullist numlist outdent indent | removeformat | help',
        content_style: 'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; font-size: 14px; }'
    });
}

// Handle file uploads with preview
function initFileUpload(inputSelector, previewSelector) {
    const input = document.querySelector(inputSelector);
    const preview = document.querySelector(previewSelector);
    
    if (!input || !preview) return;
    
    input.addEventListener('change', function() {
        preview.innerHTML = '';
        
        Array.from(this.files).forEach(file => {
            const item = document.createElement('div');
            item.className = 'file-preview-item';
            
            const icon = document.createElement('i');
            if (file.type.includes('pdf')) {
                icon.className = 'fas fa-file-pdf';
            } else if (file.type.includes('word')) {
                icon.className = 'fas fa-file-word';
            } else if (file.type.includes('sheet') || file.type.includes('excel')) {
                icon.className = 'fas fa-file-excel';
            } else {
                icon.className = 'fas fa-file';
            }
            
            const name = document.createElement('span');
            name.textContent = file.name;
            
            item.appendChild(icon);
            item.appendChild(name);
            preview.appendChild(item);
        });
    });
}

// Handle collaboration form submission
function initCollaborationForm() {
    const form = document.getElementById('collaborationForm');
    if (!form) return;
    
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const formData = new FormData(this);
        formData.append('content', tinymce.get('comment').getContent());
        
        fetch(this.action, {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                window.location.reload();
            } else {
                alert(data.error || 'Error saving collaboration');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            alert('Error saving collaboration');
        });
    });
}

// Handle legal office selection and representative loading
function initLegalOfficeSelect() {
    const officeSelect = document.querySelector('select[name="office_id"]');
    const representativesList = document.getElementById('representativesList');
    
    if (!officeSelect || !representativesList) return;
    
    officeSelect.addEventListener('change', function() {
        const officeId = this.value;
        if (!officeId) {
            representativesList.innerHTML = '';
            return;
        }
        
        fetch(`/legal-office/${officeId}/representatives/json`)
            .then(response => response.json())
            .then(data => {
                representativesList.innerHTML = data.representatives.map(rep => `
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" 
                               name="representatives" value="${rep.id}" 
                               id="rep${rep.id}">
                        <label class="form-check-label" for="rep${rep.id}">
                            ${rep.name} (${rep.position})
                            <small class="text-muted d-block">${rep.email}</small>
                        </label>
                    </div>
                `).join('');
            })
            .catch(error => {
                console.error('Error:', error);
                representativesList.innerHTML = '<p class="text-danger">Error loading representatives</p>';
            });
    });
}

// Initialize all collaboration features
document.addEventListener('DOMContentLoaded', function() {
    initTinyMCE('#comment');
    initFileUpload('#attachments', '#filePreview');
    initCollaborationForm();
    initLegalOfficeSelect();
}); 