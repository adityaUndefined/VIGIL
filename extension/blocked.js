const params = new URLSearchParams(location.search);
document.querySelector('#target').textContent = params.get('target') || 'The current page';
document.querySelector('#close').addEventListener('click', () => window.close());
