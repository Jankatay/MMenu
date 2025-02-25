#ifndef STYLE_H
#define STYLE_H

#define CATPPUCCIN_MACCHIATO
#include "catppuccin.h"
#include "raygui.h"

void setCatppuccinColors() {
	GuiSetStyle(DEFAULT, BORDER_COLOR_NORMAL, 0x838383ff);
	GuiSetStyle(DEFAULT, BASE_COLOR_NORMAL, 0xc9c9c9ff);
	GuiSetStyle(DEFAULT, TEXT_COLOR_NORMAL, 0x686868ff);
	GuiSetStyle(DEFAULT, BORDER_COLOR_FOCUSED, 0x5bb2d9ff);
	GuiSetStyle(DEFAULT, BASE_COLOR_FOCUSED, 0xc9effeff);
	GuiSetStyle(DEFAULT, TEXT_COLOR_FOCUSED, 0x6c9bbcff);
	GuiSetStyle(DEFAULT, BORDER_COLOR_PRESSED, 0x0492c7ff);
	GuiSetStyle(DEFAULT, BASE_COLOR_PRESSED, 0x97e8ffff);
	GuiSetStyle(DEFAULT, TEXT_COLOR_PRESSED, 0x368bafff);
	GuiSetStyle(DEFAULT, BORDER_COLOR_DISABLED, 0xb5c1c2ff);
	GuiSetStyle(DEFAULT, BASE_COLOR_DISABLED, 0xe6e9e9ff);
	GuiSetStyle(DEFAULT, TEXT_COLOR_DISABLED, 0xaeb7b8ff);
}

#endif 
