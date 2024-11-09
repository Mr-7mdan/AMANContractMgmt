// Add this function to handle form submission
function handleFormSubmit(event) {
    event.preventDefault();
    
    // Get selected representatives
    const selectedReps = [];
    document.querySelectorAll('#selectedRepresentatives input[type="hidden"]').forEach(input => {
        selectedReps.push(input.value);
    });
    
    // Create form data
    const formData = new FormData(event.target);
    
    // Add representatives to form data
    selectedReps.forEach(repId => {
        formData.append('representative_ids[]', repId);  // Match the name in the backend
    });
    
    // Submit form
    fetch(event.target.action, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (response.ok) {
            window.location.href = '/collaborations';
        } else {
            throw new Error('Error creating collaboration');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error creating collaboration');
    });
}

// Make sure the form has an event listener
document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('collaborationForm');
    if (form) {
        form.addEventListener('submit', handleFormSubmit);
    }
}); 