#include "raylib.h"
#define RAYGUI_IMPLEMENTATION
#include "raygui.h"

int main() {
	InitWindow(800, 400, "test");
	SetTargetFPS(10);

	bool showMessageBox = false;

	while(!WindowShouldClose()) {
		BeginDrawing();
		ClearBackground(GetColor(GuiGetStyle(DEFAULT, BACKGROUND_COLOR)));
		if (GuiButton((Rectangle){24,24,120,30}, "#191#Show Message")) {
			showMessageBox = true;
		}
		if (showMessageBox) {
			int result = GuiMessageBox((Rectangle){85, 70, 250, 100}, 
					"#191#Message Box", "Hi! This is a message!", "Nice;Cool");
			showMessageBox = result < 0;
		}
		EndDrawing();
	}
	CloseWindow();
	return 0;
}
