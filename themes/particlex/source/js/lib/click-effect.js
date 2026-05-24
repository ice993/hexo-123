(function () {
    const colors = ["#ff4757", "#2ed573", "#1e90ff", "#ffa502", "#eccc68", "#a29bfe", "#fd79a8"];

    function rand(min, max) { return Math.random() * (max - min) + min; }

    function spawnRipple(x, y, color) {
        var el = document.createElement("div");
        el.style.cssText = [
            "position:fixed",
            "left:" + x + "px",
            "top:" + y + "px",
            "width:0px",
            "height:0px",
            "border-radius:50%",
            "border:3px solid " + color,
            "pointer-events:none",
            "user-select:none",
            "z-index:99998",
            "transform:translate(-50%,-50%)",
            "opacity:0.8",
        ].join(";");
        document.body.appendChild(el);
        var start = null;
        var duration = 600;
        var maxSize = rand(60, 100);
        function animate(ts) {
            if (!start) start = ts;
            var p = (ts - start) / duration;
            if (p >= 1) { el.remove(); return; }
            var size = maxSize * p;
            el.style.width = size + "px";
            el.style.height = size + "px";
            el.style.opacity = (1 - p) * 0.7;
            requestAnimationFrame(animate);
        }
        requestAnimationFrame(animate);
    }

    function spawnDot(x, y) {
        var el = document.createElement("div");
        var size = Math.floor(rand(12, 22));
        var color = colors[Math.floor(Math.random() * colors.length)];
        var angle = rand(0, Math.PI * 2);
        var speed = rand(80, 160);
        var vx = Math.cos(angle) * speed;
        var vy = Math.sin(angle) * speed;
        var start = null;
        var duration = rand(700, 1000);

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
            if (!start) start = ts;
            var elapsed = ts - start;
            var p = elapsed / duration;
            if (p >= 1) { el.remove(); return; }
            el.style.left = (x + vx * p) + "px";
            el.style.top = (y + vy * p + 0.5 * 250 * p * p) + "px";
            el.style.opacity = 1 - p;
            requestAnimationFrame(animate);
        }
        requestAnimationFrame(animate);
    }

    document.addEventListener("click", function (e) {
        var color = colors[Math.floor(Math.random() * colors.length)];
        spawnRipple(e.clientX, e.clientY, color);
        var count = Math.floor(rand(6, 10));
        for (var i = 0; i < count; i++) spawnDot(e.clientX, e.clientY);
    });
})();
