document.addEventListener('DOMContentLoaded', function() {
    // HTMX logging
    htmx.logger = function(elt, event, data) {
        if(console) {
            console.log(event, elt, data);
        }
    }
    
    // Handle modal content updates
    document.body.addEventListener('htmx:afterSwap', function(evt) {
        console.log('Content swapped:', evt.detail.target);
        if (evt.detail.target.closest('.modal-content')) {
            console.log('Modal content updated');
            const modalElement = evt.detail.target.closest('.modal');
            if (modalElement) {
                const modal = new bootstrap.Modal(modalElement);
                modal.show();
            }
        }
    });

    // Handle modal closing
    document.addEventListener('click', function(evt) {
        if (evt.target.classList.contains('btn-close') || 
            evt.target.classList.contains('btn-secondary')) {
            const modalElement = evt.target.closest('.modal');
            if (modalElement) {
                const modal = bootstrap.Modal.getInstance(modalElement);
                if (modal) {
                    modal.hide();
                }
            }
        }
    });
});

// Add the showModal function
window.showModal = function(modalId) {
    console.log('Showing modal:', modalId);
    const modalElement = document.getElementById(modalId);
    if (!modalElement) {
        console.error('Modal element not found:', modalId);
        return;
    }
    
    const modal = new bootstrap.Modal(modalElement);
    modal.show();
}

// Handle PDF viewer
document.addEventListener('htmx:afterSettle', function(evt) {
    if (evt.detail.target.id === 'pdfViewer') {
        const iframe = evt.detail.target.querySelector('iframe');
        if (iframe) {
            iframe.style.width = '100%';
            iframe.style.height = '600px';
            iframe.style.border = 'none';
        }
    }
});

// Prevent row click when clicking on buttons or select
document.addEventListener('click', function(evt) {
    if (evt.target.closest('button, select')) {
        evt.stopPropagation();
    }
});