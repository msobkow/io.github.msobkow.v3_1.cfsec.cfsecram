
// Description: Java 25 in-memory RAM DbIO implementation for ISOCtry.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOCtryTable in-memory RAM DbIO implementation
 *	for ISOCtry.
 */
public class CFSecRamISOCtryTable
	implements ICFSecISOCtryTable
{
	private ICFSecSchema schema;
	private Map< Short,
				CFSecBuffISOCtry > dictByPKey
		= new HashMap< Short,
				CFSecBuffISOCtry >();
	private Map< CFSecBuffISOCtryByISOCodeIdxKey,
			CFSecBuffISOCtry > dictByISOCodeIdx
		= new HashMap< CFSecBuffISOCtryByISOCodeIdxKey,
			CFSecBuffISOCtry >();
	private Map< CFSecBuffISOCtryByNameIdxKey,
			CFSecBuffISOCtry > dictByNameIdx
		= new HashMap< CFSecBuffISOCtryByNameIdxKey,
			CFSecBuffISOCtry >();

	public CFSecRamISOCtryTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffISOCtry ensureRec(ICFSecISOCtry rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecISOCtry.CLASS_CODE) {
				return( ((CFSecBuffISOCtryDefaultFactory)(schema.getFactoryISOCtry())).ensureRec((ICFSecISOCtry)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOCtry createISOCtry( ICFSecAuthorization Authorization,
		ICFSecISOCtry iBuff )
	{
		final String S_ProcName = "createISOCtry";
		
		CFSecBuffISOCtry Buff = (CFSecBuffISOCtry)ensureRec(iBuff);
		Short pkey;
		pkey = schema.nextISOCtryIdGen();
		Buff.setRequiredISOCtryId( pkey );
		CFSecBuffISOCtryByISOCodeIdxKey keyISOCodeIdx = (CFSecBuffISOCtryByISOCodeIdxKey)schema.getFactoryISOCtry().newByISOCodeIdxKey();
		keyISOCodeIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecBuffISOCtryByNameIdxKey keyNameIdx = (CFSecBuffISOCtryByNameIdxKey)schema.getFactoryISOCtry().newByNameIdxKey();
		keyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByISOCodeIdx.containsKey( keyISOCodeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCtryCodeIdx",
				"ISOCtryCodeIdx",
				keyISOCodeIdx );
		}

		if( dictByNameIdx.containsKey( keyNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCtryNameIdx",
				"ISOCtryNameIdx",
				keyNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByISOCodeIdx.put( keyISOCodeIdx, Buff );

		dictByNameIdx.put( keyNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecISOCtry.CLASS_CODE) {
				CFSecBuffISOCtry retbuff = ((CFSecBuffISOCtry)(schema.getFactoryISOCtry().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOCtry readDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerived";
		ICFSecISOCtry buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry lockDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOCtry.lockDerived";
		ICFSecISOCtry buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCtry.readAllDerived";
		ICFSecISOCtry[] retList = new ICFSecISOCtry[ dictByPKey.values().size() ];
		Iterator< CFSecBuffISOCtry > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecISOCtry readDerivedByISOCodeIdx( ICFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerivedByISOCodeIdx";
		CFSecBuffISOCtryByISOCodeIdxKey key = (CFSecBuffISOCtryByISOCodeIdxKey)schema.getFactoryISOCtry().newByISOCodeIdxKey();

		key.setRequiredISOCode( ISOCode );
		ICFSecISOCtry buff;
		if( dictByISOCodeIdx.containsKey( key ) ) {
			buff = dictByISOCodeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerivedByNameIdx";
		CFSecBuffISOCtryByNameIdxKey key = (CFSecBuffISOCtryByNameIdxKey)schema.getFactoryISOCtry().newByNameIdxKey();

		key.setRequiredName( Name );
		ICFSecISOCtry buff;
		if( dictByNameIdx.containsKey( key ) ) {
			buff = dictByNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtry.readDerivedByIdIdx() ";
		ICFSecISOCtry buff;
		if( dictByPKey.containsKey( ISOCtryId ) ) {
			buff = dictByPKey.get( ISOCtryId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry readRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOCtry.readRec";
		ICFSecISOCtry buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCtry.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry lockRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecISOCtry buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOCtry.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOCtry[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCtry.readAllRec";
		ICFSecISOCtry buff;
		ArrayList<ICFSecISOCtry> filteredList = new ArrayList<ICFSecISOCtry>();
		ICFSecISOCtry[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtry.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOCtry[0] ) );
	}

	public ICFSecISOCtry readRecByIdIdx( ICFSecAuthorization Authorization,
		short ISOCtryId )
	{
		final String S_ProcName = "CFSecRamISOCtry.readRecByIdIdx() ";
		ICFSecISOCtry buff = readDerivedByIdIdx( Authorization,
			ISOCtryId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtry.CLASS_CODE ) ) {
			return( (ICFSecISOCtry)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOCtry readRecByISOCodeIdx( ICFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCtry.readRecByISOCodeIdx() ";
		ICFSecISOCtry buff = readDerivedByISOCodeIdx( Authorization,
			ISOCode );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtry.CLASS_CODE ) ) {
			return( (ICFSecISOCtry)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOCtry readRecByNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCtry.readRecByNameIdx() ";
		ICFSecISOCtry buff = readDerivedByNameIdx( Authorization,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOCtry.CLASS_CODE ) ) {
			return( (ICFSecISOCtry)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOCtry updateISOCtry( ICFSecAuthorization Authorization,
		ICFSecISOCtry iBuff )
	{
		CFSecBuffISOCtry Buff = (CFSecBuffISOCtry)ensureRec(iBuff);
		Short pkey = Buff.getPKey();
		CFSecBuffISOCtry existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCtry",
				"Existing record not found",
				"Existing record not found",
				"ISOCtry",
				"ISOCtry",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCtry",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffISOCtryByISOCodeIdxKey existingKeyISOCodeIdx = (CFSecBuffISOCtryByISOCodeIdxKey)schema.getFactoryISOCtry().newByISOCodeIdxKey();
		existingKeyISOCodeIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecBuffISOCtryByISOCodeIdxKey newKeyISOCodeIdx = (CFSecBuffISOCtryByISOCodeIdxKey)schema.getFactoryISOCtry().newByISOCodeIdxKey();
		newKeyISOCodeIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecBuffISOCtryByNameIdxKey existingKeyNameIdx = (CFSecBuffISOCtryByNameIdxKey)schema.getFactoryISOCtry().newByNameIdxKey();
		existingKeyNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffISOCtryByNameIdxKey newKeyNameIdx = (CFSecBuffISOCtryByNameIdxKey)schema.getFactoryISOCtry().newByNameIdxKey();
		newKeyNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyISOCodeIdx.equals( newKeyISOCodeIdx ) ) {
			if( dictByISOCodeIdx.containsKey( newKeyISOCodeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCtry",
					"ISOCtryCodeIdx",
					"ISOCtryCodeIdx",
					newKeyISOCodeIdx );
			}
		}

		if( ! existingKeyNameIdx.equals( newKeyNameIdx ) ) {
			if( dictByNameIdx.containsKey( newKeyNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCtry",
					"ISOCtryNameIdx",
					"ISOCtryNameIdx",
					newKeyNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< Short, CFSecBuffISOCtry > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByISOCodeIdx.remove( existingKeyISOCodeIdx );
		dictByISOCodeIdx.put( newKeyISOCodeIdx, Buff );

		dictByNameIdx.remove( existingKeyNameIdx );
		dictByNameIdx.put( newKeyNameIdx, Buff );

		return(Buff);
	}

	public void deleteISOCtry( ICFSecAuthorization Authorization,
		ICFSecISOCtry iBuff )
	{
		final String S_ProcName = "CFSecRamISOCtryTable.deleteISOCtry() ";
		CFSecBuffISOCtry Buff = (CFSecBuffISOCtry)ensureRec(iBuff);
		int classCode;
		Short pkey = (Short)(Buff.getPKey());
		CFSecBuffISOCtry existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCtry",
				pkey );
		}
					schema.getTableISOCtryLang().deleteISOCtryLangByCtryIdx( Authorization,
						existing.getRequiredISOCtryId() );
					schema.getTableISOCtryCcy().deleteISOCtryCcyByCtryIdx( Authorization,
						existing.getRequiredISOCtryId() );
		CFSecBuffISOCtryByISOCodeIdxKey keyISOCodeIdx = (CFSecBuffISOCtryByISOCodeIdxKey)schema.getFactoryISOCtry().newByISOCodeIdxKey();
		keyISOCodeIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecBuffISOCtryByNameIdxKey keyNameIdx = (CFSecBuffISOCtryByNameIdxKey)schema.getFactoryISOCtry().newByNameIdxKey();
		keyNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Short, CFSecBuffISOCtry > subdict;

		dictByPKey.remove( pkey );

		dictByISOCodeIdx.remove( keyISOCodeIdx );

		dictByNameIdx.remove( keyNameIdx );

	}
	public void deleteISOCtryByIdIdx( ICFSecAuthorization Authorization,
		Short argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffISOCtry cur;
		LinkedList<CFSecBuffISOCtry> matchSet = new LinkedList<CFSecBuffISOCtry>();
		Iterator<CFSecBuffISOCtry> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtry> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtry)(schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId() ));
			deleteISOCtry( Authorization, cur );
		}
	}

	public void deleteISOCtryByISOCodeIdx( ICFSecAuthorization Authorization,
		String argISOCode )
	{
		CFSecBuffISOCtryByISOCodeIdxKey key = (CFSecBuffISOCtryByISOCodeIdxKey)schema.getFactoryISOCtry().newByISOCodeIdxKey();
		key.setRequiredISOCode( argISOCode );
		deleteISOCtryByISOCodeIdx( Authorization, key );
	}

	public void deleteISOCtryByISOCodeIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryByISOCodeIdxKey argKey )
	{
		CFSecBuffISOCtry cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCtry> matchSet = new LinkedList<CFSecBuffISOCtry>();
		Iterator<CFSecBuffISOCtry> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtry> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtry)(schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId() ));
			deleteISOCtry( Authorization, cur );
		}
	}

	public void deleteISOCtryByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffISOCtryByNameIdxKey key = (CFSecBuffISOCtryByNameIdxKey)schema.getFactoryISOCtry().newByNameIdxKey();
		key.setRequiredName( argName );
		deleteISOCtryByNameIdx( Authorization, key );
	}

	public void deleteISOCtryByNameIdx( ICFSecAuthorization Authorization,
		ICFSecISOCtryByNameIdxKey argKey )
	{
		CFSecBuffISOCtry cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOCtry> matchSet = new LinkedList<CFSecBuffISOCtry>();
		Iterator<CFSecBuffISOCtry> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOCtry> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOCtry)(schema.getTableISOCtry().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCtryId() ));
			deleteISOCtry( Authorization, cur );
		}
	}
}
