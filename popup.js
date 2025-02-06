document.addEventListener('DOMContentLoaded', function() {
	const scanButton = document.getElementById('scanButton');
	const resultDiv = document.getElementById('result');
	const resultTitle = document.getElementById('resultTitle');
	const resultIcon = document.querySelector('.result-icon');
	const confidenceFill = document.getElementById('confidenceFill');
	const threatLevel = document.getElementById('threatLevel');
	const featuresList = document.getElementById('featuresList');
	const featuresDiv = document.getElementById('features');

	function formatFeatureName(feature) {
		return feature
			.replace(/_/g, ' ')
			.split(' ')
			.map(word => word.charAt(0).toUpperCase() + word.slice(1))
			.join(' ');
	}

	function updateUI(response) {
		const { is_phishing, confidence, features, threat_level } = response;
		
		// Show result section with animation
		resultDiv.style.display = 'block';
		resultDiv.className = `result ${is_phishing ? 'unsafe' : 'safe'}`;
		
		// Update result header
		resultIcon.textContent = is_phishing ? '⚠️' : '✅';
		resultTitle.textContent = is_phishing ? 'Potentially Unsafe' : 'Safe';
		
		// Animate confidence bar
		setTimeout(() => {
			confidenceFill.style.width = `${confidence * 100}%`;
			// Remove backgroundColor setting as we're using gradient in CSS
			confidenceFill.style.background = 'linear-gradient(to right, #00FFA9, #FF0084)';
		}, 100);
		
		// Update threat level with animation
		threatLevel.className = `threat-level ${threat_level}`;
		threatLevel.textContent = threat_level.toUpperCase();
		
		// Update features list with staggered animation
		featuresList.innerHTML = '';
		const hasFeatures = Object.values(features).some(v => v);
		
		if (hasFeatures) {
			Object.entries(features).forEach(([feature, isPresent]) => {
				if (isPresent) {
					const featureItem = document.createElement('div');
					featureItem.className = 'feature-item';
					featureItem.innerHTML = `
						<span class="feature-icon" style="color: rgba(255, 0, 132, 0.9);">⚠️</span>
						<span class="feature-text">${formatFeatureName(feature)}</span>
					`;
					featuresList.appendChild(featureItem);
				}
			});
		} else {
			const noFeatures = document.createElement('div');
			noFeatures.className = 'feature-item';
			noFeatures.innerHTML = '<span class="feature-text">No suspicious features detected</span>';
			featuresList.appendChild(noFeatures);
		}

		// Show features section with animation
		setTimeout(() => {
			featuresDiv.classList.add('visible');
		}, 300);
	}

	scanButton.addEventListener('click', async () => {
		// Update button state with loading animation
		scanButton.disabled = true;
		scanButton.classList.add('loading');
		scanButton.innerHTML = '<span>Scanning...</span>';
		
		// Reset previous results
		resultDiv.style.display = 'none';
		featuresDiv.classList.remove('visible');
		
		try {
			const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
			const url = tab.url;

			chrome.runtime.sendMessage({ action: 'analyzeUrl', url }, response => {
				updateUI(response);
				
				// Reset button state
				scanButton.disabled = false;
				scanButton.classList.remove('loading');
				scanButton.innerHTML = '<span>Scan Current Page</span>';
			});
		} catch (error) {
			console.error('Error:', error);
			scanButton.disabled = false;
			scanButton.classList.remove('loading');
			scanButton.innerHTML = '<span>Scan Current Page</span>';
		}
	});
});