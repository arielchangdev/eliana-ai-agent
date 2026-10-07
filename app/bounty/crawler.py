"""Bounty ?�喳?�????

?�虫? BountyCrawler ?��???��??? Bug Bounty ?�喳???? Trust_Score??????????��????�葫?�鈭�??"""



import asyncio

import json

import logging

import random

from datetime import datetime, timezone

from typing import Any, Callable, Optional

from urllib.parse import urlparse



import httpx

from bs4 import BeautifulSoup



from app.bounty.enums import PlatformType, ScanTool

from app.bounty.database import get_bounty_db

from app.bounty.errors import PlatformCrawlError, RateLimitError

from app.bounty.models import (

    BountyProgram,

    ChangeEvent,

    PLATFORM_WEIGHTS,

    ProgramScope,

    WhoisVerification,

)



logger = logging.getLogger(__name__)





# White-listed platform domain mapping

_WHITELISTED_DOMAINS: dict[str, PlatformType] = {

    "hackerone.com": PlatformType.HACKERONE,

    "www.hackerone.com": PlatformType.HACKERONE,

    "bugcrowd.com": PlatformType.BUGCROWD,

    "www.bugcrowd.com": PlatformType.BUGCROWD,

    "intigriti.com": PlatformType.INTIGRITI,

    "www.intigriti.com": PlatformType.INTIGRITI,

    "app.intigriti.com": PlatformType.INTIGRITI,

    "yeswehack.com": PlatformType.YESWEHACK,

    "www.yeswehack.com": PlatformType.YESWEHACK,

}



# ?�喳??? URL ??

_PLATFORM_URLS: dict[PlatformType, str] = {

    PlatformType.HACKERONE: "https://hackerone.com/directory/programs",

    PlatformType.BUGCROWD: "https://bugcrowd.com/programs",

    PlatformType.INTIGRITI: "https://app.intigriti.com/programs",

    PlatformType.YESWEHACK: "https://yeswehack.com/programs",

}





async def crawl_with_backoff(

    crawl_fn: Callable[..., Any],

    *args: Any,

    initial_wait: float = 60.0,

    max_wait: float = 1800.0,

    max_retries: int = 5,

    **kwargs: Any,

) -> Any:

    """?????�?�?????岫�???

    - ???? 60 ???��?????1.5??    - ???�???30 ??

    - ? jitter ?�? thundering herd

    - HTTP 429 ?�輻 Retry-After header ???



    Args:

        crawl_fn: ?�銵????�亦???        *args: ?????crawl_fn ???��???�?        initial_wait: ???????????�?60??        max_wait: ??��????????????1800??0 ????        max_retries: ??��???��?�?�??�?5??        **kwargs: ?????crawl_fn ????????

    Returns:

        crawl_fn ????�潦?

    Raises:

        RateLimitError: ?岫�?????????        PlatformCrawlError: ??????�日??��???��???    """

    wait = initial_wait



    for attempt in range(max_retries):

        try:

            return await crawl_fn(*args, **kwargs)

        except RateLimitError as e:

            if attempt == max_retries - 1:

                raise

            # ????�輻 Retry-After header ??           
            retry_after = e.retry_after

            if retry_after > 0:

                actual_wait = min(retry_after, max_wait)

            else:

                actual_wait = min(wait, max_wait)

            # ? jitter??5%???thundering herd

            jitter = actual_wait * random.uniform(-0.25, 0.25)

            sleep_time = max(0, actual_wait + jitter)

            logger.warning(

                "Rate limited (attempt %d/%d), waiting %.1f seconds before retry",

                attempt + 1,

                max_retries,

                sleep_time,

            )

            await asyncio.sleep(sleep_time)

            # ????           
            wait = min(wait * 2, max_wait)

        except PlatformCrawlError as e:

            if attempt == max_retries - 1:

                raise

            if not e.retryable:

                raise

            # ? jitter

            jitter = wait * random.uniform(-0.25, 0.25)

            sleep_time = max(0, wait + jitter)

            logger.warning(

                "Crawl error (attempt %d/%d): %s, waiting %.1f seconds",

                attempt + 1,

                max_retries,

                e.message,

                sleep_time,

            )

            await asyncio.sleep(sleep_time)

            wait = min(wait * 2, max_wait)



    # Should not reach here, but just in case

    return await crawl_fn(*args, **kwargs)





class BountyCrawler:

    """Bug Bounty ?�喳?祈�???HackerOne/Bugcrowd/Intigriti/YesWeHack??"""



    def __init__(self, http_client: Optional[httpx.AsyncClient] = None, backoff_initial: float = 60.0, backoff_max: float = 1800.0, backoff_retries: int = 5) -> None:

        """??????

        Args:

            http_client: ????httpx.AsyncClient ?�虫???�??��???�??��?�?????                         ?�??????????��????? client??        """

        self._http_client = http_client
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._backoff_retries = backoff_retries



    async def _get_client(self) -> httpx.AsyncClient:

        """?????��?HTTP ?�Ｘ?�胯?"""

        if self._http_client is not None:

            return self._http_client

        return httpx.AsyncClient(

            timeout=30.0,

            headers={

                "User-Agent": "Eliana-BountyCrawler/1.0",

                "Accept": "text/html,application/xhtml+xml",

            },

            follow_redirects=True,

        )



    async def crawl_all_platforms(self) -> list[BountyProgram]:

        """???????�喳??�頨????

        ?�???PlatformType???��?????crawl_platform??        ????????crawl_with_backoff ???????

        Returns:

            ?????? BountyProgram ???        """

        all_programs: list[BountyProgram] = []



        for platform in PlatformType:

            try:

                programs = await crawl_with_backoff(

                    self.crawl_platform, platform,

                    initial_wait=self._backoff_initial,

                    max_wait=self._backoff_max,

                    max_retries=self._backoff_retries,

                )

                all_programs.extend(programs)

                logger.info(

                    "Crawled %d programs from %s",

                    len(programs),

                    platform.value,

                )

            except (RateLimitError, PlatformCrawlError) as e:

                logger.error(

                    "Failed to crawl %s after retries: %s",

                    platform.value,

                    e.message,

                )

                # Continue with other platforms even if one fails

                continue



        return all_programs



    async def crawl_platform(self, platform: PlatformType) -> list[BountyProgram]:

        """??????�喳??�頨????

        ?�輻 httpx ???�喳??��? BeautifulSoup4 ??? HTML??        ???��???�西?? BountyProgram ??�辣??

        Args:

            platform: ????�喳????

        Returns:

            ?��??�喳?????BountyProgram ????

        Raises:

            RateLimitError: ?�喳? HTTP 429??            PlatformCrawlError: ??? HTTP ??��???        """

        url = _PLATFORM_URLS[platform]

        client = await self._get_client()

        owns_client = self._http_client is None



        try:

            response = await client.get(url)



            # Handle HTTP 429 rate limiting

            if response.status_code == 429:

                retry_after = 60.0

                retry_header = response.headers.get("Retry-After")

                if retry_header:

                    try:

                        retry_after = float(retry_header)

                    except (ValueError, TypeError):

                        pass

                raise RateLimitError(platform=platform, retry_after=retry_after)



            # Handle other HTTP errors

            if response.status_code >= 400:

                raise PlatformCrawlError(

                    message=f"HTTP {response.status_code} from {platform.value}",

                    platform=platform,

                    status_code=response.status_code,

                )



            # Parse HTML with BeautifulSoup4

            html_content = response.text

            programs = self._parse_platform_html(platform, html_content)

            return programs



        finally:

            if owns_client:

                await client.aclose()



    def _parse_platform_html(

        self, platform: PlatformType, html: str

    ) -> list[BountyProgram]:

        """?�??�喳????? HTML ???��????

        ?��????????HTML ???��????????????

        Args:

            platform: ?�喳????            html: ?�喳????HTML ??��???

        Returns:

            ??HTML ?��???? BountyProgram ????        """

        parsers = {

            PlatformType.HACKERONE: self._parse_hackerone_html,

            PlatformType.BUGCROWD: self._parse_bugcrowd_html,

            PlatformType.INTIGRITI: self._parse_intigriti_html,

            PlatformType.YESWEHACK: self._parse_yeswehack_html,

        }

        parser = parsers[platform]

        return parser(html)



    def _parse_hackerone_html(self, html: str) -> list[BountyProgram]:

        """??? HackerOne ?�喳 HTML??

        HackerOne ?????��?�?? div ???        ???�??????????

        Args:

            html: HackerOne ???HTML ??��???

        Returns:

            ????BountyProgram ????        """

        soup = BeautifulSoup(html, "html.parser")

        programs: list[BountyProgram] = []



        # HackerOne uses program cards with data attributes or specific CSS classes

        program_elements = soup.select(

            "[data-program], .program-card, .directory-list__item, article"

        )



        for elem in program_elements:

            program = self._extract_program_from_element(

                elem, PlatformType.HACKERONE

            )

            if program:

                programs.append(program)



        return programs



    def _parse_bugcrowd_html(self, html: str) -> list[BountyProgram]:

        """??? Bugcrowd ?�喳 HTML??

        Args:

            html: Bugcrowd ???HTML ??��???

        Returns:

            ????BountyProgram ????        """

        soup = BeautifulSoup(html, "html.parser")

        programs: list[BountyProgram] = []



        program_elements = soup.select(

            ".program-card, .bounty-card, [data-program-id], article"

        )



        for elem in program_elements:

            program = self._extract_program_from_element(

                elem, PlatformType.BUGCROWD

            )

            if program:

                programs.append(program)



        return programs



    def _parse_intigriti_html(self, html: str) -> list[BountyProgram]:

        """??? Intigriti ?�喳 HTML??

        Args:

            html: Intigriti ???HTML ??��???

        Returns:

            ????BountyProgram ????        """

        soup = BeautifulSoup(html, "html.parser")

        programs: list[BountyProgram] = []



        program_elements = soup.select(

            ".program-item, .program-card, [data-program], article"

        )



        for elem in program_elements:

            program = self._extract_program_from_element(

                elem, PlatformType.INTIGRITI

            )

            if program:

                programs.append(program)



        return programs



    def _parse_yeswehack_html(self, html: str) -> list[BountyProgram]:

        """??? YesWeHack ?�喳 HTML??

        Args:

            html: YesWeHack ???HTML ??��???

        Returns:

            ????BountyProgram ????        """

        soup = BeautifulSoup(html, "html.parser")

        programs: list[BountyProgram] = []



        program_elements = soup.select(

            ".program-item, .program-card, [data-program], article"

        )



        for elem in program_elements:

            program = self._extract_program_from_element(

                elem, PlatformType.YESWEHACK

            )

            if program:

                programs.append(program)



        return programs



    def _extract_program_from_element(

        self, elem: Any, platform: PlatformType

    ) -> Optional[BountyProgram]:

        """??HTML ???? BountyProgram ????

        ?????��???��????????HTML ???��????????        ?????賭�???data-* ?��??�摰?CSS class ???�摰�?

        Args:

            elem: BeautifulSoup ??HTML ????            platform: ???�喳??

        Returns:

            ????????BountyProgram???None??        """

        # ?�????�?
        name = ""

        name_elem = elem.select_one(

            "h2, h3, h4, .program-name, .title, [data-name]"

        )

        if name_elem:

            name = name_elem.get_text(strip=True)

        elif elem.get("data-name"):

            name = elem["data-name"]



        if not name:

            return None



        # ?�?????�?
        org = ""

        org_elem = elem.select_one(

            ".organization, .company, .org-name, [data-organization]"

        )

        if org_elem:

            org = org_elem.get_text(strip=True)

        elif elem.get("data-organization"):

            org = elem["data-organization"]



        # ?�???�喳??ID

        platform_program_id = (

            elem.get("data-program-id")

            or elem.get("data-program")

            or elem.get("data-id")

            or ""

        )



        # ?�???????
        domains: list[str] = []

        scope_elems = elem.select(".scope-item, .domain, [data-domain]")

        for scope_elem in scope_elems:

            domain_text = scope_elem.get_text(strip=True)

            if domain_text:

                domains.append(domain_text)



        # ?�??????

        bounty_low = 0.0

        bounty_high = 0.0

        bounty_elem = elem.select_one(

            ".bounty-range, .reward, [data-bounty-min], [data-bounty-max]"

        )

        if bounty_elem:

            if bounty_elem.get("data-bounty-min"):

                try:

                    bounty_low = float(bounty_elem["data-bounty-min"])

                except (ValueError, TypeError):

                    pass

            if bounty_elem.get("data-bounty-max"):

                try:

                    bounty_high = float(bounty_elem["data-bounty-max"])

                except (ValueError, TypeError):

                    pass



        now = datetime.now(timezone.utc)



        return BountyProgram(

            platform=platform,

            platform_program_id=str(platform_program_id),

            name=name,

            organization=org,

            domains=domains,

            bounty_range_low=bounty_low,

            bounty_range_high=bounty_high,

            crawled_at=now,

            updated_at=now,

        )



    def is_whitelisted_platform(self, url: str) -> bool:

        """???URL ??��??�??桀?????��????

        Return True if and only if the URL's domain belongs to one of the

        four whitelisted platforms: HackerOne, Bugcrowd, Intigriti, YesWeHack.

        Return False for all other domains.



        Args:

            url: ???? URL ?�葡??

        Returns:

            True ??URL ?��??�??桀?????血? False??        """

        try:

            parsed = urlparse(url)

            hostname = parsed.hostname

            if hostname is None:

                return False

            hostname = hostname.lower()

            # Check exact match or if it's a subdomain of a whitelisted platform

            for domain in _WHITELISTED_DOMAINS:

                if hostname == domain or hostname.endswith("." + domain):

                    return True

            return False

        except Exception:

            return False



    def calculate_trust_score(self, program: BountyProgram) -> float:

        """?????Trust_Score???�???

        ??????        - ?�喳?????�ackerOne=1.0, Bugcrowd=1.0, Intigriti=0.9, YesWeHack=0.9??        - ?�摮??��???365???�踹?, <30??????        - ?�脣????>50=?�踹?, 0=????

        ? 0.0~1.0 ??Trust_Score??        Score increases monotonically with higher platform weight,

        longer active duration, and higher public report count.



        Args:

            program: BountyProgram ???�∪???

        Returns:

            ??0.0 ??1.0 ???縑�?�???        """

        # 1. Platform weight factor (0.0 ~ 1.0)

        platform_weight = PLATFORM_WEIGHTS.get(program.platform, 0.5)



        # 2. Active duration factor (0.0 ~ 1.0)

        if program.active_since is not None:

            now = datetime.now(timezone.utc)

            # Ensure active_since is timezone-aware for comparison

            active_since = program.active_since

            if active_since.tzinfo is None:

                active_since = active_since.replace(tzinfo=timezone.utc)

            delta_days = (now - active_since).days

            if delta_days < 0:

                delta_days = 0

            # Linear interpolation: 0 days -> 0.0, 365 days -> 1.0, capped at 1.0

            duration_factor = min(delta_days / 365.0, 1.0)

        else:

            duration_factor = 0.0



        # 3. Public report count factor (0.0 ~ 1.0)

        # Linear interpolation: 0 reports -> 0.0, 50 reports -> 1.0, capped at 1.0

        report_count = max(program.public_reports_count, 0)

        report_factor = min(report_count / 50.0, 1.0)



        # Weighted combination: platform=40%, duration=30%, reports=30%

        raw_score = (

            0.4 * platform_weight

            + 0.3 * duration_factor

            + 0.3 * report_factor

        )



        # Clamp to [0.0, 1.0]

        return max(0.0, min(1.0, raw_score))



    def parse_scope(self, raw_scope: dict) -> ProgramScope:

        """????�蝭??�????�????�???

        Extract domains, ip_ranges, excluded_paths, allowed_tools, max_scan_rate

        from raw scope dict into a ProgramScope dataclass.



        Args:

            raw_scope: ?????��??�???��??��??                - domains: list[str]

                - ip_ranges: list[str]

                - excluded_paths: list[str]

                - allowed_tools: list[str] (?��??迂摮??

                - max_scan_rate: int | None



        Returns:

            ???? ProgramScope dataclass??        """

        # Parse domains

        domains = raw_scope.get("domains", [])

        if not isinstance(domains, list):

            domains = []

        domains = [str(d) for d in domains if d]



        # Parse IP ranges

        ip_ranges = raw_scope.get("ip_ranges", [])

        if not isinstance(ip_ranges, list):

            ip_ranges = []

        ip_ranges = [str(r) for r in ip_ranges if r]



        # Parse excluded paths

        excluded_paths = raw_scope.get("excluded_paths", [])

        if not isinstance(excluded_paths, list):

            excluded_paths = []

        excluded_paths = [str(p) for p in excluded_paths if p]



        # Parse allowed tools (convert string names to ScanTool enum)

        raw_tools = raw_scope.get("allowed_tools", [])

        if not isinstance(raw_tools, list):

            raw_tools = []

        allowed_tools: list[ScanTool] = []

        for tool_name in raw_tools:

            try:

                allowed_tools.append(ScanTool(str(tool_name).lower()))

            except (ValueError, KeyError):

                # Skip unknown tool names

                continue



        # Parse max scan rate

        max_scan_rate = raw_scope.get("max_scan_rate")

        if max_scan_rate is not None:

            try:

                max_scan_rate = int(max_scan_rate)

                if max_scan_rate <= 0:

                    max_scan_rate = None

            except (ValueError, TypeError):

                max_scan_rate = None



        return ProgramScope(

            domains=domains,

            ip_ranges=ip_ranges,

            excluded_paths=excluded_paths,

            allowed_tools=allowed_tools,

            max_scan_rate=max_scan_rate,

        )



    # --- Task_Scheduler ???�? ---



    def register_crawl_schedule(

        self,

        scheduler: Optional[Any] = None,

        cron_expression: str = "0 0 * * *",

    ) -> dict[str, Any]:

        """?��????????��????Task_Scheduler??

        ?? Task_Scheduler ?��?????????��????        ??Task_Scheduler ????��??????�身???�????�???

        Args:

            scheduler: Task_Scheduler ?�虫???�???                       ?�?None??????��?????�阡??��????            cron_expression: cron ???�券????身瘥???????                            ??????????��??

        Returns:

            ???��???��???��????task_id?chedule?andler ????        """

        schedule_config: dict[str, Any] = {

            "task_id": "bounty_crawl_all_platforms",

            "task_name": "Bounty Platform Crawl",

            "schedule": cron_expression,

            "handler": "app.bounty.crawler:BountyCrawler.crawl_all_platforms",

            "retry_policy": {

                "max_retries": 3,

                "backoff_initial": 60.0,

                "backoff_max": 1800.0,

            },

            "enabled": True,

        }



        if scheduler is not None:

            try:

                # Attempt to register with Task_Scheduler if available

                scheduler.register_task(schedule_config)

                logger.info(

                    "Registered crawl schedule: %s", cron_expression

                )

            except (AttributeError, TypeError) as e:

                logger.warning(

                    "Task_Scheduler not fully available, "

                    "schedule config saved for later: %s",

                    e,

                )



        return schedule_config



    # --- Placeholder async methods (to be implemented in later tasks) ---



    async def detect_changes(self, programs: list[BountyProgram]) -> list[ChangeEvent]:

        """比�?資�?庫�??�測?��??��??��?計畫??


        Compare provided programs list against what's stored in the database.

        Programs present in input but not in DB are identified as "new".

        Programs whose scope differs between DB and input are identified as "scope_update".

        No false change events are produced for unchanged programs.



        Args:

            programs: ?��?從平?�爬?�到?��??��??��?


        Returns:

            ?�測?��?變更事件清單??
        """

        change_events: list[ChangeEvent] = []

        now = datetime.now(timezone.utc)



        db = await get_bounty_db()

        try:

            # Fetch all existing programs from DB indexed by platform_program_id

            cursor = await db.execute(

                "SELECT platform_program_id, scope_in, scope_out FROM bounty_programs"

            )

            rows = await cursor.fetchall()

            existing: dict[str, tuple[str, str]] = {}

            for row in rows:

                # row: (platform_program_id, scope_in, scope_out)

                existing[row[0]] = (row[1], row[2])



            for program in programs:

                pid = program.platform_program_id

                if pid not in existing:

                    # New program detected

                    event = ChangeEvent(

                        program_id=program.id,

                        change_type="new",

                        details=f"New program detected: {program.name}",

                        detected_at=now,

                    )

                    change_events.append(event)

                else:

                    # Compare scope_in and scope_out

                    db_scope_in, db_scope_out = existing[pid]

                    current_scope_in = json.dumps(program.scope_in, sort_keys=True)

                    current_scope_out = json.dumps(program.scope_out, sort_keys=True)



                    # Normalize DB values for comparison

                    try:

                        normalized_db_scope_in = json.dumps(

                            json.loads(db_scope_in), sort_keys=True

                        )

                    except (json.JSONDecodeError, TypeError):

                        normalized_db_scope_in = "[]"



                    try:

                        normalized_db_scope_out = json.dumps(

                            json.loads(db_scope_out), sort_keys=True

                        )

                    except (json.JSONDecodeError, TypeError):

                        normalized_db_scope_out = "[]"



                    if (current_scope_in != normalized_db_scope_in or

                            current_scope_out != normalized_db_scope_out):

                        event = ChangeEvent(

                            program_id=program.id,

                            change_type="scope_update",

                            details="Scope changed for program",

                            detected_at=now,

                        )

                        change_events.append(event)



            # Store change events in DB

            for event in change_events:

                await db.execute(

                    """INSERT INTO change_events (program_id, change_type, details, detected_at)

                       VALUES (?, ?, ?, ?)""",

                    (

                        event.program_id,

                        event.change_type,

                        event.details,

                        event.detected_at.isoformat(),

                    ),

                )

            await db.commit()

        finally:

            await db.close()



        return change_events





    async def verify_whois(self, program: BountyProgram) -> WhoisVerification:

        """WHOIS 交�?比�??��??��??��?計畫�?��組�???


        Use python-whois to query WHOIS for the first domain in program.domains.

        Compare the registrant organization with program.organization.

        Update program.whois_verified in the database.



        Args:

            program: 待�?證�? BountyProgram??


        Returns:

            WhoisVerification 驗�?結�???
        """

        now = datetime.now(timezone.utc)



        # Determine domain to query

        domain = program.domains[0] if program.domains else ""

        if not domain:

            # No domain to verify

            verification = WhoisVerification(

                domain="",

                registrant_org="",

                claimed_org=program.organization,

                match=False,

                verified_at=now,

            )

            await self._update_whois_verified(program.id, False)

            return verification



        # Query WHOIS

        registrant_org = ""

        match = False

        try:

            import whois



            w = whois.whois(domain)

            # Extract organization from WHOIS data

            org = w.org if hasattr(w, "org") else None

            if org is None:

                org = ""

            if isinstance(org, list):

                org = org[0] if org else ""

            registrant_org = str(org) if org else ""



            # Compare registrant org with claimed org (case-insensitive)

            if registrant_org and program.organization:

                match = (

                    registrant_org.lower().strip()

                    == program.organization.lower().strip()

                )

        except Exception:

            # WHOIS query failed -> match=False, empty registrant_org

            registrant_org = ""

            match = False



        verification = WhoisVerification(

            domain=domain,

            registrant_org=registrant_org,

            claimed_org=program.organization,

            match=match,

            verified_at=now,

        )



        # Update whois_verified in database

        await self._update_whois_verified(program.id, match)



        return verification



    async def _update_whois_verified(self, program_id: str, verified: bool) -> None:

        """Update the whois_verified field in the bounty_programs table."""

        db = await get_bounty_db()

        try:

            await db.execute(

                "UPDATE bounty_programs SET whois_verified = ? WHERE id = ?",

                (1 if verified else 0, program_id),

            )

            await db.commit()

        finally:

            await db.close()



