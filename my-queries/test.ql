/**
 * @kind problem
 */

import java

from Class c, Class superclass
where superclass = c.getASupertype()
select c, "This class extends another class."
