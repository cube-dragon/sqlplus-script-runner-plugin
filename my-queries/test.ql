/**
 * @kind problem
 * @id my-queries/test
 */

import java

from MethodAccess call, Method method
where
  call.getMethod() = method
select call, "method"
