(() => {
    document.addEventListener('DOMContentLoaded', () => {
        const c = () => {
            if (window.pywebview)
                window.pywebview.api.window_init();
            else
                setTimeout(c, 10);
        }
        setTimeout(c, 10);
    });
    // set transparent background
    {
        document.body.style.backgroundColor = 'rgba(0,0,0,0)';
    }

    // title_bar
    {
        const title_bar_height = '30px';

        const title_bar = document.createElement('div');
        title_bar.className = 'pywebview-drag-region';
        title_bar.style.position = 'absolute';
        title_bar.style.top = '0';
        title_bar.style.left = '0';
        title_bar.style.width = '100vw';
        title_bar.style.height = title_bar_height;
        title_bar.style.backgroundColor = 'rgba(145,145,145,0.5)';

        const create_button = () => {
            const button = document.createElement('div');
            button.style.position = 'absolute';
            button.style.top = '7px';
            button.style.width = '15px';
            button.style.height = '15px';
            button.style.borderRadius = '50%';
            button.style.cursor = 'pointer';
            return button;
        }

        const close_button = create_button();
        close_button.style.right = '15px';
        close_button.style.backgroundColor = 'rgba(255,0,0,0.5)';
        close_button.onclick = () => {
            window.pywebview.api.window_close();
        }
        title_bar.appendChild(close_button);

        const minimize_button = create_button();
        minimize_button.style.right = '40px';
        minimize_button.style.backgroundColor = 'rgba(255,255,0,0.5)';
        minimize_button.onclick = () => {
            window.pywebview.api.window_minimize();
        }
        title_bar.appendChild(minimize_button);

        document.body.appendChild(title_bar);
    }

    // resize_bar
    {
        const resize_bar_size = '7px';
        var is_resizing = false;

        document.addEventListener('mouseup', (event) => {
            if (!is_resizing) return
            is_resizing = false
            window.pywebview.api.window_resize_end()
        });
        document.addEventListener('mousemove', (event) => {
            if (!is_resizing) return
            window.pywebview.api.window_resize_update()
        });

        const style = document.createElement('style');
        style.appendChild(document.createTextNode('.resize_bar_color_when_hover:hover {background-color: rgba(145,145,145,0.5);}'));
        document.getElementsByTagName('head')[0].appendChild(style);


        const create_resize_bar = (top = false, bottom = false, left = false, right = false) => {
            const el = document.createElement('div');
            el.style.position = 'absolute';
            el.className = 'resize_bar_color_when_hover';
            const is_tb = top || bottom;
            const is_lr = left || right;
            if (is_tb) {
                el.style.height = resize_bar_size;
                if (top) {
                    el.style.top = '0';
                } else {
                    el.style.bottom = '0';
                }
            } else {
                el.style.top = '0';
                el.style.height = '100vh';
            }
            if (is_lr) {
                el.style.width = resize_bar_size;
                if (left) {
                    el.style.left = '0';
                } else {
                    el.style.right = '0';
                }
            } else {
                el.style.left = '0';
                el.style.width = '100vw';
            }
            if (is_tb && !is_lr) {
                el.style.cursor = 'ns-resize';
            } else if (is_lr && !is_tb) {
                el.style.cursor = 'ew-resize';
            } else if (top && left || bottom && right) {
                el.style.cursor = 'nwse-resize';
            } else if (top && right || bottom && left) {
                el.style.cursor = 'nesw-resize';
            }
            const direction = [];
            if (left) direction.push('left');
            if (right) direction.push('right');
            if (top) direction.push('top');
            if (bottom) direction.push('bottom');
            const s_direction = direction.join('-');
            el.onmousedown = (event) => {
                is_resizing = true;
                window.pywebview.api.window_resize_start(s_direction);
            }
            document.body.appendChild(el);
            return el;
        }

        create_resize_bar(true, false, false, false);
        create_resize_bar(false, true, false, false);
        create_resize_bar(false, false, true, false);
        create_resize_bar(false, false, false, true);
        create_resize_bar(true, false, true, false);
        create_resize_bar(true, false, false, true);
        create_resize_bar(false, true, true, false);
        create_resize_bar(false, true, false, true);
    }
})()
