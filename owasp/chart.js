// Color palette for different risk levels
const riskColors = {
    note: '#6c757d',
    low: '#28a745',
    medium: '#ffc107',
    high: '#fd7e14',
    critical: '#dc3545'
};

// Chart configuration
const ctx = document.getElementById('myChart').getContext('2d');
const myChart = new Chart(ctx, {
    type: 'radar',
    data: {
        labels: [
            'Skill Level',
            'Motive',
            'Opportunity',
            'Size',
            'Ease of Discovery',
            'Ease of Exploit',
            'Awareness',
            'Intrusion Detection',
            'Loss of Confidentiality',
            'Loss of Integrity',
            'Loss of Availability',
            'Loss of Accountability',
            'Financial Damage',
            'Reputation Damage',
            'Non-compliance',
            'Privacy Violation'
        ],
        datasets: [{
            label: 'Risk Factors',
            data: Array(16).fill(0),
            backgroundColor: 'rgba(52, 152, 219, 0.2)',
            borderColor: 'rgba(52, 152, 219, 1)',
            borderWidth: 2,
            pointBackgroundColor: 'rgba(52, 152, 219, 1)',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: 'rgba(52, 152, 219, 1)',
            pointRadius: 4,
            pointHoverRadius: 6
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            r: {
                beginAtZero: true,
                max: 9,
                ticks: {
                    stepSize: 1
                },
                grid: {
                    color: 'rgba(0, 0, 0, 0.1)'
                },
                angleLines: {
                    color: 'rgba(0, 0, 0, 0.1)'
                },
                pointLabels: {
                    font: {
                        size: 12
                    }
                }
            }
        },
        plugins: {
            legend: {
                display: false
            },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        return `Score: ${context.raw}`;
                    }
                }
            }
        },
        animation: {
            duration: 500,
            easing: 'easeInOutQuart'
        }
    }
});

// Function to calculate likelihood score
function calculateLikelihoodScore() {
    const threatAgentFactors = [
        parseFloat(document.getElementById('skill-level').value),
        parseFloat(document.getElementById('motive').value),
        parseFloat(document.getElementById('opportunity').value),
        parseFloat(document.getElementById('size').value)
    ];

    const vulnerabilityFactors = [
        parseFloat(document.getElementById('ease-of-discovery').value),
        parseFloat(document.getElementById('ease-of-exploit').value),
        parseFloat(document.getElementById('awareness').value),
        parseFloat(document.getElementById('intrusion-detection').value)
    ];

    const threatAgentScore = threatAgentFactors.reduce((a, b) => a + b, 0) / threatAgentFactors.length;
    const vulnerabilityScore = vulnerabilityFactors.reduce((a, b) => a + b, 0) / vulnerabilityFactors.length;

    return (threatAgentScore + vulnerabilityScore) / 2;
}

// Function to calculate impact score
function calculateImpactScore() {
    const technicalImpactFactors = [
        parseFloat(document.getElementById('loss-confidentiality').value),
        parseFloat(document.getElementById('loss-integrity').value),
        parseFloat(document.getElementById('loss-availability').value),
        parseFloat(document.getElementById('loss-accountability').value)
    ];

    const businessImpactFactors = [
        parseFloat(document.getElementById('financial-damage').value),
        parseFloat(document.getElementById('reputation-damage').value),
        parseFloat(document.getElementById('non-compliance').value),
        parseFloat(document.getElementById('privacy-violation').value)
    ];

    const technicalScore = technicalImpactFactors.reduce((a, b) => a + b, 0) / technicalImpactFactors.length;
    const businessScore = businessImpactFactors.reduce((a, b) => a + b, 0) / businessImpactFactors.length;

    return (technicalScore + businessScore) / 2;
}

// Function to determine risk level
function determineRiskLevel(likelihood, impact) {
    if (likelihood <= 3 && impact <= 3) return 'NOTE';
    if (likelihood <= 3 && impact <= 6) return 'LOW';
    if (likelihood <= 3 && impact <= 9) return 'MEDIUM';
    if (likelihood <= 6 && impact <= 3) return 'LOW';
    if (likelihood <= 6 && impact <= 6) return 'MEDIUM';
    if (likelihood <= 6 && impact <= 9) return 'HIGH';
    if (likelihood <= 9 && impact <= 3) return 'MEDIUM';
    if (likelihood <= 9 && impact <= 6) return 'HIGH';
    return 'CRITICAL';
}

// Function to update risk rating
function updateRiskRating() {
    // Get all values
    const values = [
        parseFloat(document.getElementById('skill-level').value),
        parseFloat(document.getElementById('motive').value),
        parseFloat(document.getElementById('opportunity').value),
        parseFloat(document.getElementById('size').value),
        parseFloat(document.getElementById('ease-of-discovery').value),
        parseFloat(document.getElementById('ease-of-exploit').value),
        parseFloat(document.getElementById('awareness').value),
        parseFloat(document.getElementById('intrusion-detection').value),
        parseFloat(document.getElementById('loss-confidentiality').value),
        parseFloat(document.getElementById('loss-integrity').value),
        parseFloat(document.getElementById('loss-availability').value),
        parseFloat(document.getElementById('loss-accountability').value),
        parseFloat(document.getElementById('financial-damage').value),
        parseFloat(document.getElementById('reputation-damage').value),
        parseFloat(document.getElementById('non-compliance').value),
        parseFloat(document.getElementById('privacy-violation').value)
    ];

    // Update chart data
    myChart.data.datasets[0].data = values;
    myChart.update();

    // Calculate scores
    const likelihoodScore = calculateLikelihoodScore();
    const impactScore = calculateImpactScore();
    const riskLevel = determineRiskLevel(likelihoodScore, impactScore);

    // Update score displays with animation
    const likelihoodElement = document.getElementById('likelihood-score');
    const impactElement = document.getElementById('impact-score');
    const riskLevelElement = document.getElementById('risk-level');

    // Remove previous classes
    likelihoodElement.className = 'risk-score';
    impactElement.className = 'risk-score';
    riskLevelElement.className = 'risk-score';

    // Add new classes based on risk level
    riskLevelElement.classList.add(riskLevel.toLowerCase());

    // Update values with animation
    likelihoodElement.textContent = likelihoodScore.toFixed(1);
    impactElement.textContent = impactScore.toFixed(1);
    riskLevelElement.textContent = riskLevel;

    // Add pulse animation
    likelihoodElement.style.animation = 'pulse 0.5s ease-in-out';
    impactElement.style.animation = 'pulse 0.5s ease-in-out';
    riskLevelElement.style.animation = 'pulse 0.5s ease-in-out';

    // Update severity matrix highlight
    const matrix = document.querySelector('.severity-matrix');
    const cells = matrix.querySelectorAll('td');
    cells.forEach(cell => cell.classList.remove('highlight'));

    // Find and highlight the corresponding cell
    const likelihoodIndex = Math.floor(likelihoodScore / 3);
    const impactIndex = Math.floor(impactScore / 3);
    const targetCell = matrix.rows[impactIndex + 1].cells[likelihoodIndex + 1];
    targetCell.classList.add('highlight');
}

// Add event listeners to all select elements
const selectElements = document.querySelectorAll('select');
selectElements.forEach(select => {
    select.addEventListener('change', updateRiskRating);
});

// Debounce function to limit the number of updates
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

// Initialize the chart with default values
updateRiskRating(); 