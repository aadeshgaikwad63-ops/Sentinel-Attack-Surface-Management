// SentinelASM — Chart.js dark theme defaults
if (typeof Chart !== 'undefined') {
  Chart.defaults.color = '#96A3B8';
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.font.size = 11.5;
  Chart.defaults.borderColor = 'rgba(148,163,184,.10)';
  Chart.defaults.plugins.legend.labels.usePointStyle = true;
  Chart.defaults.plugins.legend.labels.boxWidth = 7;
  Chart.defaults.plugins.legend.labels.boxHeight = 7;
  Chart.defaults.plugins.tooltip.backgroundColor = '#1F2937';
  Chart.defaults.plugins.tooltip.borderColor = 'rgba(148,163,184,.22)';
  Chart.defaults.plugins.tooltip.borderWidth = 1;
  Chart.defaults.plugins.tooltip.titleFont = { family: "'Space Grotesk', sans-serif", weight: '700' };
  Chart.defaults.plugins.tooltip.bodyFont = { family: "'JetBrains Mono', monospace" };
  Chart.defaults.plugins.tooltip.padding = 10;
  Chart.defaults.plugins.tooltip.cornerRadius = 8;
}

const SENTINEL_PALETTE = {
  green:  '#17C990',
  blue:   '#3E8EF7',
  amber:  '#F5A524',
  red:    '#F0465B',
  purple: '#8B6BF2',
  grid:   'rgba(148,163,184,.08)'
};

function sentinelGradient(ctx, color, alphaTop = .35, alphaBottom = 0){
  const g = ctx.createLinearGradient(0, 0, 0, 220);
  g.addColorStop(0, hexToRgba(color, alphaTop));
  g.addColorStop(1, hexToRgba(color, alphaBottom));
  return g;
}
function hexToRgba(hex, a){
  const v = hex.replace('#','');
  const r = parseInt(v.substring(0,2),16), g = parseInt(v.substring(2,4),16), b = parseInt(v.substring(4,6),16);
  return `rgba(${r},${g},${b},${a})`;
}
