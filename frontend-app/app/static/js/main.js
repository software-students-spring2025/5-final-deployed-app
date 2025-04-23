// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    // Get all alert elements
    const alerts = document.querySelectorAll('.alert');
    
    // Set timeout for each alert
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bootstrapAlert = bootstrap.Alert.getOrCreateInstance(alert);
            bootstrapAlert.close();
        }, 5000);
    });
    
    // Enable all tooltips
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(function(tooltip) {
        new bootstrap.Tooltip(tooltip);
    });
    
    // Enable all popovers
    const popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
    popovers.forEach(function(popover) {
        new bootstrap.Popover(popover);
    });
});

// Confirm deletion of posts
function confirmDelete(formId) {
    if (confirm('Are you sure you want to delete this post? This action cannot be undone.')) {
        document.getElementById(formId).submit();
    }
    return false;
}

// Format dates to relative time (e.g., "2 hours ago")
document.addEventListener('DOMContentLoaded', function() {
    const timeElements = document.querySelectorAll('.relative-time');
    
    timeElements.forEach(function(element) {
        const timestamp = element.getAttribute('data-timestamp');
        if (timestamp) {
            const date = new Date(timestamp);
            const now = new Date();
            const diffInSeconds = Math.floor((now - date) / 1000);
            
            let timeAgo = '';
            
            if (diffInSeconds < 60) {
                timeAgo = `${diffInSeconds} seconds ago`;
            } else if (diffInSeconds < 3600) {
                const minutes = Math.floor(diffInSeconds / 60);
                timeAgo = `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
            } else if (diffInSeconds < 86400) {
                const hours = Math.floor(diffInSeconds / 3600);
                timeAgo = `${hours} hour${hours > 1 ? 's' : ''} ago`;
            } else if (diffInSeconds < 604800) {
                const days = Math.floor(diffInSeconds / 86400);
                timeAgo = `${days} day${days > 1 ? 's' : ''} ago`;
            } else {
                const options = { year: 'numeric', month: 'short', day: 'numeric' };
                timeAgo = date.toLocaleDateString(undefined, options);
            }
            
            element.textContent = timeAgo;
        }
    });
});