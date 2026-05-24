(function () {
    const colors = ["#ff4757", "#2ed573", "#1e90ff", "#ffa502", "#eccc68", "#a29bfe", "#fd79a8", "#ff6b81", "#00d2d3", "#ff9f43"];

    function rand(min, max) { return Math.random() * (max - min) + min; }

    // 大波纹 — 3层，尺寸更大
    function spawnRipples(x, y) {
        for (var i = 0; i < 3; i++) {
            (function (delay) {
                setTimeout(function () {
                    var el = document.createElement("div");
                    var color = colors[Math.floor(Math.random() * colors.length)];
                    var maxSize = rand(160, 280);
                    el.style.cssText = [
                        "position:fixed",
                        "left:" + x + "px",
                        "top:" + y + "px",
                        "width:0","height:0",
                        "border-radius:50%",
                        "border:3px solid " + color,
                        "pointer-events:none",
                        "z-index:99997",
                        "transform:translate(-50%,-50%)",
                        "box-shadow:0 0 8px 2px " + color,
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
                        el.style.opacity = (1 - p) * 0.9;
                        requestAnimationFrame(animate);
                    }
                    requestAnimationFrame(animate);
                }, delay);
            })(i * 100);
        }
    }

    // 大气泡 — 尺寸30-60px，带厚实发光
    function spawnBubbles(x, y) {
        var count = Math.floor(rand(10, 16));
        for (var i = 0; i < count; i++) {
            (function () {
                var el = document.createElement("div");
                var size = rand(28, 58);
                var color = colors[Math.floor(Math.random() * colors.length)];
                var angle = rand(0, Math.PI * 2);
                var speed = rand(150, 320);
                var vx = Math.cos(angle) * speed;
                var vy = Math.sin(angle) * speed;
                var gravity = rand(300, 500);
                var dur = rand(800, 1300);
                var start = null;
                el.style.cssText = [
                    "position:fixed",
                    "width:" + size + "px",
                    "height:" + size + "px",
                    "border-radius:50%",
                    "background:" + color,
                    "pointer-events:none",
                    "z-index:99999",
                    "left:" + x + "px",
                    "top:" + y + "px",
                    "transform:translate(-50%,-50%)",
                    "box-shadow:0 0 " + (size * 0.8) + "px " + (size * 0.4) + "px " + color,
                ].join(";");
                document.body.appendChild(el);
                function animate(ts) {
                    if (!start) start = ts;
                    var p = (ts - start) / dur;
                    if (p >= 1) { el.remove(); return; }
                    var ease = 1 - Math.pow(1 - p, 2);
                    el.style.left = (x + vx * ease) + "px";
                    el.style.top = (y + vy * ease + 0.5 * gravity * p * p) + "px";
                    el.style.opacity = p < 0.5 ? 1 : (1 - p) / 0.5;
                    var s = size * (1 - p * 0.4);
                    el.style.width = s + "px";
                    el.style.height = s + "px";
                    requestAnimationFrame(animate);
                }
                requestAnimationFrame(animate);
            })();
        }
    }

    // 中等粒子填充密度
    function spawnSparks(x, y) {
        var count = Math.floor(rand(12, 18));
        for (var i = 0; i < count; i++) {
            (function () {
                var el = document.createElement("div");
                var size = rand(6, 14);
                var color = colors[Math.floor(Math.random() * colors.length)];
                var angle = rand(0, Math.PI * 2);
                var speed = rand(80, 200);
                var vx = Math.cos(angle) * speed;
                var vy = Math.sin(angle) * speed - rand(40, 100);
                var dur = rand(500, 900);
                var start = null;
                el.style.cssText = [
                    "position:fixed",
                    "width:" + size + "px",
                    "height:" + size + "px",
                    "border-radius:50%",
                    "background:#fff",
                    "pointer-events:none",
                    "z-index:100000",
                    "left:" + x + "px",
                    "top:" + y + "px",
                    "transform:translate(-50%,-50%)",
                    "box-shadow:0 0 6px 3px " + color,
                ].join(";");
                document.body.appendChild(el);
                function animate(ts) {
                    if (!start) start = ts;
                    var p = (ts - start) / dur;
                    if (p >= 1) { el.remove(); return; }
                    el.style.left = (x + vx * p) + "px";
                    el.style.top = (y + vy * p + 0.5 * 400 * p * p) + "px";
                    el.style.opacity = 1 - p;
                    requestAnimationFrame(animate);
                }
                requestAnimationFrame(animate);
            })();
        }
    }

    // 中心爆闪 — 更大更亮
    function spawnFlash(x, y) {
        var color = colors[Math.floor(Math.random() * colors.length)];
        var el = document.createElement("div");
        el.style.cssText = [
            "position:fixed",
            "left:" + x + "px",
            "top:" + y + "px",
            "width:0","height:0",
            "border-radius:50%",
            "background:" + color,
            "pointer-events:none",
            "z-index:99998",
            "transform:translate(-50%,-50%)",
            "box-shadow:0 0 60px 30px " + color,
        ].join(";");
        document.body.appendChild(el);
        var start = null, dur = 350, maxSize = rand(60, 90);
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
        spawnSparks(e.clientX, e.clientY);
    });
})();
