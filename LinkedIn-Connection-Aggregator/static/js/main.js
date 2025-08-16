// LinkedIn Connection Aggregator - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips and popovers
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // File upload handling
    const fileInput = document.getElementById('csvFile');
    if (fileInput) {
        fileInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const fileName = file.name;
                const fileSize = (file.size / 1024 / 1024).toFixed(2); // MB
                
                // Validate file type
                if (!fileName.toLowerCase().endsWith('.csv')) {
                    alert('Please select a CSV file.');
                    e.target.value = '';
                    return;
                }
                
                // Validate file size (max 16MB)
                if (file.size > 16 * 1024 * 1024) {
                    alert('File size too large. Maximum size is 16MB.');
                    e.target.value = '';
                    return;
                }
                
                // Update form text
                const formText = document.querySelector('.form-text');
                if (formText) {
                    formText.innerHTML = `Selected: ${fileName} (${fileSize} MB)`;
                }
            }
        });
    }

    // Form submission loading states
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
                submitBtn.disabled = true;
                
                // Re-enable after 30 seconds as fallback
                setTimeout(() => {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }, 30000);
            }
        });
    });

    // Search suggestions
    const searchInput = document.querySelector('input[name="query"]');
    if (searchInput) {
        const suggestions = [
            "Who knows someone at Google?",
            "Show me connections from Microsoft",
            "Find people at startups",
            "Connections at Amazon",
            "Who works at Apple?",
            "People from consulting firms",
            "Show me tech company connections"
        ];
        
        searchInput.addEventListener('focus', function() {
            // Could implement autocomplete here
        });
        
        // Add example suggestions on empty search
        searchInput.addEventListener('input', function(e) {
            if (e.target.value.trim() === '') {
                // Show placeholder with examples
            }
        });
    }

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        if (alert.classList.contains('alert-success') || alert.classList.contains('alert-info')) {
            setTimeout(() => {
                const alertInstance = new bootstrap.Alert(alert);
                alertInstance.close();
            }, 5000);
        }
    });

    // Smooth scrolling for internal links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Table row highlighting
    const tableRows = document.querySelectorAll('.table tbody tr');
    tableRows.forEach(row => {
        row.addEventListener('mouseenter', function() {
            this.style.backgroundColor = 'rgba(13, 202, 240, 0.1)';
        });
        
        row.addEventListener('mouseleave', function() {
            this.style.backgroundColor = '';
        });
    });

    // Copy to clipboard functionality for email addresses
    const emailLinks = document.querySelectorAll('.text-muted');
    emailLinks.forEach(link => {
        if (link.textContent.includes('@')) {
            link.style.cursor = 'pointer';
            link.title = 'Click to copy email';
            
            link.addEventListener('click', function() {
                navigator.clipboard.writeText(this.textContent).then(() => {
                    // Show temporary success message
                    const originalText = this.textContent;
                    this.textContent = 'Copied!';
                    this.style.color = '#198754';
                    
                    setTimeout(() => {
                        this.textContent = originalText;
                        this.style.color = '';
                    }, 1500);
                });
            });
        }
    });

    // Analytics data loading (if needed)
    const analyticsContainer = document.getElementById('analytics');
    if (analyticsContainer) {
        loadAnalytics();
    }

    // Connection count animation
    const countElements = document.querySelectorAll('.card h4');
    countElements.forEach(element => {
        const finalCount = parseInt(element.textContent);
        if (!isNaN(finalCount) && finalCount > 0) {
            animateCounter(element, 0, finalCount, 1000);
        }
    });
});

// Utility functions
function animateCounter(element, start, end, duration) {
    const startTime = Date.now();
    const timer = setInterval(() => {
        const elapsed = Date.now() - startTime;
        const progress = elapsed / duration;
        
        if (progress >= 1) {
            element.textContent = end;
            clearInterval(timer);
        } else {
            const current = Math.floor(start + (end - start) * progress);
            element.textContent = current;
        }
    }, 16); // ~60fps
}

function loadAnalytics() {
    fetch('/api/analytics')
        .then(response => response.json())
        .then(data => {
            if (data.companies) {
                updateCompanyChart(data.companies);
            }
            if (data.trends) {
                updateTrendsChart(data.trends);
            }
        })
        .catch(error => {
            console.error('Error loading analytics:', error);
        });
}

function updateCompanyChart(companies) {
    // Implementation for company chart if Chart.js is included
    console.log('Company data:', companies);
}

function updateTrendsChart(trends) {
    // Implementation for trends chart if Chart.js is included
    console.log('Trends data:', trends);
}

// Search enhancement functions
function highlightSearchTerms(text, searchTerm) {
    if (!searchTerm) return text;
    
    const regex = new RegExp(`(${searchTerm})`, 'gi');
    return text.replace(regex, '<mark>$1</mark>');
}

function debounce(func, wait) {
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

// Function to perform search when recent search is clicked
function performSearch(query) {
    // Set the search input value
    const searchInput = document.querySelector('input[name="query"]');
    if (searchInput) {
        searchInput.value = query;
        
        // Submit the search form
        const searchForm = searchInput.closest('form');
        if (searchForm) {
            searchForm.submit();
        }
    }
    return false; // Prevent default link behavior
}

// Export functions for potential use
window.ConnectionAggregator = {
    animateCounter,
    loadAnalytics,
    highlightSearchTerms,
    debounce,
    performSearch
};
