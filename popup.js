document.addEventListener('DOMContentLoaded', async function() {
	const resultDiv = document.getElementById('result');
	const resultIcon = document.querySelector('.result-icon');
	const resultTitle = document.getElementById('resultTitle');
	const reportButton = document.getElementById('reportButton');
	const confidenceFill = document.getElementById('confidenceFill');
	const threatLevel = document.getElementById('threatLevel');
	const featuresList = document.getElementById('featuresList');
	const featuresDiv = document.getElementById('features');

	// Initially hide the report button
	reportButton.style.display = 'none';

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
		
		// Show confidence bar
		confidenceFill.style.width = `${confidence * 100}%`;
		
		// Update threat level
		threatLevel.className = `threat-level ${threat_level}`;
		threatLevel.textContent = threat_level.toUpperCase();
		
		// Update features list
		featuresList.innerHTML = '';
		const hasFeatures = Object.values(features).some(v => v);

		
		if (hasFeatures) {
			Object.entries(features).forEach(([feature, isPresent], index) => {
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
		featuresDiv.classList.add('visible');

		// Show/hide report button based on threat level
		reportButton.style.display = (threat_level === 'high' || threat_level === 'medium') ? 'block' : 'none';
	}

	// Automatically trigger scan when popup opens
	try {
		const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
		const url = tab.url;

		// Show loading state while preserving structure
		resultDiv.style.display = 'block';
		resultTitle.textContent = 'Analyzing...';
		resultIcon.textContent = '⚡';
		confidenceFill.style.width = '0%';
		threatLevel.textContent = '';
		featuresList.innerHTML = `
			<div class="feature-item">
				<span class="loading-icon">⚡</span>
				<span class="feature-text">Analyzing URL features...</span>
			</div>
		`;
		featuresDiv.classList.add('visible');

		chrome.runtime.sendMessage({ action: 'analyzeUrl', url }, response => {
			console.log('Received response:', response);
			if (response) {
				console.log('Confidence:', response.confidence);
				console.log('Features:', response.features);
				console.log('Threat Level:', response.threat_level);
				updateUI(response);
			} else {
				console.error('No response received');
				resultTitle.textContent = 'Error';
				resultIcon.textContent = '⚠️';
				featuresList.innerHTML = `
					<div class="feature-item">
						<span style="color: rgba(255, 0, 132, 0.9);">⚠️</span>
						<span class="feature-text">Error: No response received</span>
					</div>
				`;
			}
		});
	} catch (error) {
		console.error('Error:', error);
		resultTitle.textContent = 'Error';
		resultIcon.textContent = '⚠️';
		featuresList.innerHTML = `
			<div class="feature-item">
				<span style="color: rgba(255, 0, 132, 0.9);">⚠️</span>
				<span class="feature-text">Error scanning URL: ${error.message}</span>
			</div>
		`;
	}

	// Report button click handler
	reportButton.addEventListener('click', async () => {
		try {
			const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
			const subject = encodeURIComponent('Report Suspicious Website');
			const body = encodeURIComponent(`Suspicious URL: ${tab.url}\n\nThis website has been detected as potentially malicious by the URL Safety Scanner extension.`);
			const mailtoUrl = `mailto:mpcyberpolice@gmail.com?subject=${subject}&body=${body}`;
			
			chrome.tabs.create({ url: mailtoUrl });
			chrome.tabs.create({ url: 'https://cybercrime.gov.in/' });
			
			chrome.notifications.create('report_' + Date.now(), {
				type: 'basic',
				iconUrl: 'icons/icon128.png',
				title: 'Report Initiated',
				message: 'Opening email client and cyber crime portal to report the malicious website.'
			});
		} catch (error) {
			console.error('Error reporting website:', error);
		}
	});
});
