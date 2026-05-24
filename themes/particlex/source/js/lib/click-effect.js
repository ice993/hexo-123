(function () {
    const colors = ["#ff4757", "#2ed573", "#1e90ff", "#ffa502", "#eccc68", "#a29bfe", "#fd79a8", "#ff6b81", "#00d2d3", "#ff9f43"];

    function rand(min, max) { return Math.random() * (max - min) + min; }

    // 多层波纹
    function spawnRipples(x, y) {
        var count = 3;
        for (var i = 0; i < count; i++) {
            (function (delay) {
                setTimeout(function () {
                    var el = document.createElement("div");
                    var color = colors[Math.floor(Math.random() * colors.length)];
                    var maxSize = rand(80, 160);
                    el.style.cssText = [
                        "position:fixed",
                        "left:" + x + "px",
                        "top:" + y + "px",
                        "width:0","height:0",
                        "border-radius:50%",
                        "border:2px solid " + color,
                        "pointer-events:none",
                        "z-index:99997",
                        "transform:translate(-50%,-50%)",
                    ].join(";");
                    document.body.appendChild(el);
                    var start = null, dur = rand(500, 800);
                    function animate(ts) {
                        if (!start) start = ts;
                        var p = (ts - start) / dur;
                        if (p >= 1) { el.remove(); return; }
                        var s = maxSize * p;
                        el.style.width = s + "px";
                        el.style.height = s + "px";
                        el.style.opacity = (1 - p) * 0.8;
                        requestAnimationFrame(animate);
                    }
                    requestAnimationFrame(animate);
                }, delay);
            })(i * 80);
        }
    }

    // 大粒子：向四周爆炸飞出
    function spawnBurst(x, y) {
        var count = Math.floor(rand(14, 20));
        for (var i = 0; i < count; i++) {
            (function () {
                var el = document.createElement("div");
                var size = rand(8, 20);
                var color = colors[Math.floor(Math.random() * colors.length)];
                var angle = rand(0, Math.PI * 2);
                var speed = rand(120, 260);
                var vx = Math.cos(angle) * speed;
                var vy = Math.sin(angle) * speed;
                var gravity = rand(200, 400);
                var dur = rand(600, 1100);
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
                    "box-shadow:0 0 " + (size * 1.5) + "px " + color,
                ].join(";");
                document.body.appendChild(el);
                function animate(ts) {
                    if (!start) start = ts;
                    var p = (ts - start) / dur;
                    if (p >= 1) { el.remove(); return; }
                    var ease = 1 - Math.pow(1 - p, 2);
                    el.style.left = (x + vx * ease) + "px";
                    el.style.top = (y + vy * ease + 0.5 * gravity * p * p) + "px";
                    el.style.opacity = p < 0.6 ? 1 : (1 - p) / 0.4;
                    el.style.width = (size * (1 - p * 0.5)) + "px";
                    el.style.height = (size * (1 - p * 0.5)) + "px";
                    requestAnimationFrame(animate);
                }
                requestAnimationFrame(animate);
            })();
        }
    }

    // 小星星拖尾粒子
    function spawnSparks(x, y) {
        var count = Math.floor(rand(8, 14));
        for (var i = 0; i < count; i++) {
            (function () {
                var el = document.createElement("div");
                var size = rand(3, 7);
                var color = colors[Math.floor(Math.random() * colors.length)];
                var angle = rand(0, Math.PI * 2);
                var speed = rand(60, 140);
                var vx = Math.cos(angle) * speed;
                var vy = Math.sin(angle) * speed - rand(30, 80);
                var dur = rand(400, 700);
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
                    "box-shadow:0 0 4px 2px " + color,
                ].join(";");
                document.body.appendChild(el);
                function animate(ts) {
                    if (!start) start = ts;
                    var p = (ts - start) / dur;
                    if (p >= 1) { el.remove(); return; }
                    el.style.left = (x + vx * p) + "px";
                    el.style.top = (y + vy * p + 0.5 * 300 * p * p) + "px";
                    el.style.opacity = 1 - p;
                    requestAnimationFrame(animate);
                }
                requestAnimationFrame(animate);
            })();
        }
    }

    // 中心闪光
    function spawnFlash(x, y) {
        var el = document.createElement("div");
        var color = colors[Math.floor(Math.random() * colors.length)];
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
            "box-shadow:0 0 30px 15px " + color,
        ].join(";");
        document.body.appendChild(el);
        var start = null, dur = 300, maxSize = rand(30, 50);
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
        spawnBurst(e.clientX, e.clientY);
        spawnSparks(e.clientX, e.clientY);
    });
})();
