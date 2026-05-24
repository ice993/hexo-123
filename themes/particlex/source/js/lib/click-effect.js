(function () {
    const colors = ["#ff4757", "#2ed573", "#1e90ff", "#ffa502", "#eccc68", "#a29bfe", "#fd79a8"];

    function randomBetween(min, max) {
        return Math.random() * (max - min) + min;
    }

    document.addEventListener("click", function (e) {
        var count = Math.floor(randomBetween(5, 9));
        for (var i = 0; i < count; i++) {
            (function () {
                var el = document.createElement("div");
                var size = Math.floor(randomBetween(6, 14));
                var color = colors[Math.floor(Math.random() * colors.length)];
                var angle = randomBetween(0, Math.PI * 2);
                var speed = randomBetween(60, 130);
                var vx = Math.cos(angle) * speed;
                var vy = Math.sin(angle) * speed;
                var x = e.clientX;
                var y = e.clientY;
                var startTime = null;
                var duration = randomBetween(600, 900);

                el.style.cssText = [
                    "position:fixed",
                    "width:" + size + "px",
                    "height:" + size + "px",
                    "border-radius:50%",
                    "background:" + color,
                    "pointer-events:none",
                    "user-select:none",
                    "z-index:99999",
                    "left:" + x + "px",
                    "top:" + y + "px",
                    "transform:translate(-50%,-50%)",
                ].join(";");
                document.body.appendChild(el);

                function animate(ts) {
                    if (!startTime) startTime = ts;
                    var elapsed = ts - startTime;
                    var progress = elapsed / duration;
                    if (progress >= 1) {
                        el.remove();
                        return;
                    }
                    var curX = x + vx * progress;
                    var curY = y + vy * progress + 0.5 * 200 * progress * progress;
                    var opacity = 1 - progress;
                    el.style.left = curX + "px";
                    el.style.top = curY + "px";
                    el.style.opacity = opacity;
                    requestAnimationFrame(animate);
                }
                requestAnimationFrame(animate);
            })();
        }
    });
})();
