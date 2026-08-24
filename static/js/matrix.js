(function () {
  const canvas = document.getElementById("matrixCanvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const CHARS = "01KHΣΔΩΞ$#@%&+-<>/\\|";
  const COLORS = ["#00d4ff", "#5fe1ff", "#eafcff", "#2f7bff"];

  let columns, drops, speeds, fontSize;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    fontSize = Math.max(14, Math.floor(window.innerWidth / 110));
    columns = Math.floor(canvas.width / fontSize);
    drops = new Array(columns).fill(0).map(() => Math.floor(Math.random() * -40));
    speeds = new Array(columns).fill(0).map(() => 0.4 + Math.random() * 1.1);
  }

  window.addEventListener("resize", resize);
  resize();

  function draw() {
    ctx.fillStyle = "rgba(5, 5, 8, 0.15)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.font = fontSize + "px monospace";

    for (let i = 0; i < columns; i++) {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      const x = i * fontSize;
      const y = drops[i] * fontSize;

      if (Math.random() < 0.02) {
        ctx.fillStyle = "#ffffff";
      } else {
        ctx.fillStyle = COLORS[Math.floor(Math.random() * COLORS.length)];
      }
      ctx.shadowColor = "#00d4ff";
      ctx.shadowBlur = 4;
      ctx.fillText(char, x, y);
      ctx.shadowBlur = 0;

      if (y > canvas.height && Math.random() > 0.975) {
        drops[i] = 0;
      }
      drops[i] += speeds[i];
    }
    requestAnimationFrame(draw);
  }
  requestAnimationFrame(draw);
})();
