/**
 * @kind problem
 * @id my-queries/test
 */

import java

from Class c, Class superclass
where superclass = c.getASupertype()
select c, "This class extends another class."
