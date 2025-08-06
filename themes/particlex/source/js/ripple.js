document.addEventListener('click', function (e) {
  const rippleElement = e.target.closest('.ripple');
  if (!rippleElement) return;

  const rect = rippleElement.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height);
  const x = e.clientX - rect.left - size / 2;
  const y = e.clientY - rect.top - size / 2;

  const ripple = document.createElement('span');
  ripple.style.width = ripple.style.height = `${size}px`;
  ripple.style.left = `${x}px`;
  ripple.style.top = `${y}px`;

  rippleElement.appendChild(ripple);
  setTimeout(() => ripple.remove(), 600);
});
