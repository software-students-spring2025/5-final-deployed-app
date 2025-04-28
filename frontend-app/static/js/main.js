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
    
    // Format dates to relative time (e.g., "2 hours ago")
    formatRelativeTimes();
});

// Confirm deletion of posts
function confirmDelete(formId) {
    if (confirm('Are you sure you want to delete this post? This action cannot be undone.')) {
        document.getElementById(formId).submit();
    }
    return false;
}

// Format all relative times on the page
function formatRelativeTimes() {
    const timeElements = document.querySelectorAll('.relative-time');
    
    timeElements.forEach(function(element) {
        const timestamp = element.getAttribute('data-timestamp');
        if (!timestamp) return;
        
        // Handle ISO format timestamp (with T) or standard format (with space)
        let formattedTimestamp = timestamp;
        if (timestamp.includes(' ') && !timestamp.includes('T')) {
            formattedTimestamp = timestamp.replace(' ', 'T');
        }
        
        const date = new Date(formattedTimestamp);
        
        // Check if the date is valid
        if (isNaN(date.getTime())) {
            console.error('Invalid date format:', timestamp);
            element.textContent = "Unknown date";
            return;
        }
        
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        let timeAgo = '';
        
        if (diffInSeconds < 0) {
            // Future date (server/client time mismatch)
            timeAgo = "just now";
        } else if (diffInSeconds < 60) {
            timeAgo = `${diffInSeconds} second${diffInSeconds !== 1 ? 's' : ''} ago`;
        } else if (diffInSeconds < 3600) {
            const minutes = Math.floor(diffInSeconds / 60);
            timeAgo = `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
        } else if (diffInSeconds < 86400) {
            const hours = Math.floor(diffInSeconds / 3600);
            timeAgo = `${hours} hour${hours !== 1 ? 's' : ''} ago`;
        } else if (diffInSeconds < 604800) {
            const days = Math.floor(diffInSeconds / 86400);
            timeAgo = `${days} day${days !== 1 ? 's' : ''} ago`;
        } else if (diffInSeconds < 2592000) { // Less than a month
            const weeks = Math.floor(diffInSeconds / 604800);
            timeAgo = `${weeks} week${weeks !== 1 ? 's' : ''} ago`;
        } else if (diffInSeconds < 31536000) { // Less than a year
            const months = Math.floor(diffInSeconds / 2592000);
            timeAgo = `${months} month${months !== 1 ? 's' : ''} ago`;
        } else {
            const years = Math.floor(diffInSeconds / 31536000);
            timeAgo = `${years} year${years !== 1 ? 's' : ''} ago`;
        }
        
        element.textContent = timeAgo;
    });
}