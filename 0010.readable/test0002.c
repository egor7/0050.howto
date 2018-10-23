#include "tig/search.h"
#include "tig/prompt.h"
#include "tig/display.h"

/* Some
   multiline
   comment
 */

void
reset_search(struct view *view)
{
	free(view->matched_line);
	view->matched_line = NULL;
	view->matched_lines = 0;
}
