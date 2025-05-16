#ifndef _example_app_window_h_
#define _example_app_window_h_
#include <gtk/gtk.h>

G_BEGIN_DECLS

#define EXAMPLE_APP_WINDOW_TYPE (example_app_window_get_type ())
G_DECLARE_FINAL_TYPE(ExampleAppWindow, example_app_window, SHORTCUT_HANDLER, WINDOW, GtkApplicationWindow)

ExampleAppWindow *example_app_window_new(GtkApplication *app);

G_END_DECLS

#endif /* _example_app_window_h_ */
