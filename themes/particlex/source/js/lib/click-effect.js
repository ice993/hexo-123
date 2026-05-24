(function () {
    const colors = ["#ff4757", "#2ed573", "#1e90ff", "#ffa502", "#eccc68", "#a29bfe", "#fd79a8", "#ff6b81", "#00d2d3", "#ff9f43"];

    function rand(min, max) { return Math.random() * (max - min) + min; }

    // 大气泡 — 饱满圆润，带高光内阴影
    function spawnBubbles(x, y) {
        var count = Math.floor(rand(8, 13));
        for (var i = 0; i < count; i++) {
            (function () {
                var el = document.createElement("div");
                var size = rand(50, 90);
                var color = colors[Math.floor(Math.random() * colors.length)];
                var angle = rand(0, Math.PI * 2);
                var speed = rand(180, 380);
                var vx = Math.cos(angle) * speed;
                var vy = Math.sin(angle) * speed;
                var gravity = rand(400, 650);
                var dur = rand(900, 1400);
                var start = null;

                el.style.cssText = [
                    "position:fixed",
                    "width:" + size + "px",
                    "height:" + size + "px",
                    "border-radius:50%",
                    "background:radial-gradient(circle at 35% 35%, rgba(255,255,255,0.55) 0%, " + color + " 55%, rgba(0,0,0,0.15) 100%)",
                    "pointer-events:none",
                    "z-index:99999",
                    "left:" + x + "px",
                    "top:" + y + "px",
                    "transform:translate(-50%,-50%)",
                    "box-shadow:0 0 " + (size * 0.7) + "px " + (size * 0.25) + "px " + color + ", inset 0 0 " + (size * 0.3) + "px rgba(255,255,255,0.4)",
                ].join(";");
                document.body.appendChild(el);

                function animate(ts) {
                    if (!start) start = ts;
                    var p = (ts - start) / dur;
                    if (p >= 1) { el.remove(); return; }
                    var ease = 1 - Math.pow(1 - p, 2);
                    el.style.left = (x + vx * ease) + "px";
                    el.style.top = (y + vy * ease + 0.5 * gravity * p * p) + "px";
                    el.style.opacity = p < 0.45 ? 1 : (1 - p) / 0.55;
                    var s = size * (1 - p * 0.35);
                    el.style.width = s + "px";
                    el.style.height = s + "px";
                    requestAnimationFrame(animate);
                }
                requestAnimationFrame(animate);
            })();
        }
    }

    // 波纹 — 3层，粗边框+发光，尺寸大且明显
    function spawnRipples(x, y) {
        for (var i = 0; i < 3; i++) {
            (function (delay, maxSize) {
                setTimeout(function () {
                    var el = document.createElement("div");
                    var color = colors[Math.floor(Math.random() * colors.length)];
                    el.style.cssText = [
                        "position:fixed",
                        "left:" + x + "px",
                        "top:" + y + "px",
                        "width:0","height:0",
                        "border-radius:50%",
                        "border:4px solid " + color,
                        "pointer-events:none",
                        "z-index:99997",
                        "transform:translate(-50%,-50%)",
                        "box-shadow:0 0 12px 4px " + color + ", inset 0 0 8px 2px " + color,
                    ].join(";");
                    document.body.appendChild(el);
                    var start = null, dur = rand(700, 1000);
                    function animate(ts) {
                        if (!start) start = ts;
                        var p = (ts - start) / dur;
                        if (p >= 1) { el.remove(); return; }
                        var s = maxSize * p;
                        el.style.width = s + "px";
                        el.style.height = s + "px";
                        el.style.opacity = Math.pow(1 - p, 1.5);
                        requestAnimationFrame(animate);
                    }
                    requestAnimationFrame(animate);
                }, delay);
            })(i * 120, rand(200, 340));
        }
    }

    // 中心爆闪
    function spawnFlash(x, y) {
        var color = colors[Math.floor(Math.random() * colors.length)];
        var el = document.createElement("div");
        var maxSize = rand(70, 100);
        el.style.cssText = [
            "position:fixed",
            "left:" + x + "px",
            "top:" + y + "px",
            "width:0","height:0",
            "border-radius:50%",
            "background:radial-gradient(circle, #fff 0%, " + color + " 60%, transparent 100%)",
            "pointer-events:none",
            "z-index:99998",
            "transform:translate(-50%,-50%)",
            "box-shadow:0 0 80px 40px " + color,
        ].join(";");
        document.body.appendChild(el);
        var start = null, dur = 380;
        function animate(ts) {
            if (!start) start = ts;
            var p = (ts - start) / dur;
            if (p >= 1) { el.remove(); return; }
            var s = maxSize * Math.sin(p * Math.PI);
            el.style.width = s + "px";
            el.style.height = s + "px";
            el.style.opacity = Math.sin(p * Math.PI);
            requestAnimationFrame(animate);
        }
        requestAnimationFrame(animate);
    }

    document.addEventListener("click", function (e) {
        spawnFlash(e.clientX, e.clientY);
        spawnRipples(e.clientX, e.clientY);
        spawnBubbles(e.clientX, e.clientY);
    });
})();
