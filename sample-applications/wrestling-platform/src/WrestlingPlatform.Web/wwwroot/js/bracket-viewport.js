window.PinPointBracketViewport = (function () {
    const stateByElement = new WeakMap();

    function dispose(element) {
        const state = stateByElement.get(element);
        if (!state) {
            return;
        }

        element.removeEventListener("pointerdown", state.onPointerDown);
        element.removeEventListener("pointermove", state.onPointerMove);
        element.removeEventListener("pointercancel", state.onPointerUp);
        window.removeEventListener("pointerup", state.onPointerUp);
        element.removeEventListener("wheel", state.onWheel);
        element.classList.remove("is-panning");
        stateByElement.delete(element);
    }

    function center(element) {
        if (!element) {
            return;
        }

        element.scrollLeft = Math.max(0, (element.scrollWidth - element.clientWidth) / 2);
        element.scrollTop = Math.max(0, (element.scrollHeight - element.clientHeight) / 2);
    }

    function init(element, dotNetRef) {
        if (!element) {
            return;
        }

        dispose(element);

        let isDragging = false;
        let pointerId = -1;
        let startX = 0;
        let startY = 0;
        let startScrollLeft = 0;
        let startScrollTop = 0;

        const onPointerDown = (event) => {
            if (event.button !== 0) {
                return;
            }

            isDragging = true;
            pointerId = event.pointerId;
            startX = event.clientX;
            startY = event.clientY;
            startScrollLeft = element.scrollLeft;
            startScrollTop = element.scrollTop;
            element.classList.add("is-panning");

            try {
                element.setPointerCapture(pointerId);
            } catch {
                // Ignore capture failures in unsupported browsers.
            }
        };

        const onPointerMove = (event) => {
            if (!isDragging) {
                return;
            }

            const dx = event.clientX - startX;
            const dy = event.clientY - startY;
            element.scrollLeft = startScrollLeft - dx;
            element.scrollTop = startScrollTop - dy;
        };

        const onPointerUp = (event) => {
            if (!isDragging) {
                return;
            }

            isDragging = false;
            element.classList.remove("is-panning");
            if (pointerId >= 0) {
                try {
                    element.releasePointerCapture(pointerId);
                } catch {
                    // Ignore capture release failures.
                }
            }

            pointerId = -1;
        };

        const onWheel = (event) => {
            // Map-style behavior: wheel zooms, drag pans.
            event.preventDefault();
            const delta = event.deltaY < 0 ? 10 : -10;
            dotNetRef.invokeMethodAsync("OnViewportWheelZoom", delta).catch(() => {
                // Component may have been disposed.
            });
        };

        element.addEventListener("pointerdown", onPointerDown);
        element.addEventListener("pointermove", onPointerMove);
        element.addEventListener("pointercancel", onPointerUp);
        window.addEventListener("pointerup", onPointerUp);
        element.addEventListener("wheel", onWheel, { passive: false });

        stateByElement.set(element, {
            onPointerDown,
            onPointerMove,
            onPointerUp,
            onWheel
        });
    }

    return {
        init,
        center,
        dispose
    };
})();

