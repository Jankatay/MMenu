#include "shortcut-handler.h"

// Your callback function for the action
void example_app_window_printmsg (GtkWidget *widget, const char *action_name, GVariant *parameter) {
	printf("hello, world\n");
  // Run your action code here
}

// The class structure
struct _ExampleAppWindow
{
  GtkApplicationWindow parent;
};

// Definition of subclass
G_DEFINE_TYPE(ExampleAppWindow, example_app_window, GTK_TYPE_APPLICATION_WINDOW);

// Instance initialization (run for every instance)
static void
example_app_window_init (ExampleAppWindow *app)
{
}

// Class initialization (run onces for the class)
static void
example_app_window_class_init (ExampleAppWindowClass *class)
{
  // Install actions here like this
  gtk_widget_class_install_action(GTK_WIDGET_CLASS(class), "window.printmsg", NULL, example_app_window_printmsg);
}

// Constructor for window subclass
ExampleAppWindow *example_app_window_new (GtkApplication *app) {
  return g_object_new (EXAMPLE_APP_WINDOW_TYPE, "application", app, NULL);
}


